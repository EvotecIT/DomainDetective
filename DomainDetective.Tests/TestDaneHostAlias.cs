using DnsClientX;

namespace DomainDetective.Tests;

public class TestDaneHostAlias {
    [Theory]
    [InlineData("ports", 443)]
    [InlineData("services", 443)]
    [InlineData("https", 443)]
    [InlineData("smtp-mx", 25)]
    public async Task SecureHostAliasPrefersTargetTlsaBase(string route, int port) {
        using var check = new DomainHealthCheck();
        var evidenceHosts = new List<string>();
        check.DaneCertificateEvidenceOverride = (host, _, _) => {
            evidenceHosts.Add(host);
            return Task.FromResult<DaneCertificateEvidence?>(null);
        };
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            var response = new DnsResponse { Status = DnsResponseCode.NoError };
            if (name == "alias.example" && type == DnsRecordType.CNAME) {
                response.Answers = new[] {
                    new DnsAnswer { Name = name, Type = type, DataRaw = "target.example" }
                };
            } else if (name == "example.com" && type == DnsRecordType.MX) {
                response.Answers = new[] {
                    new DnsAnswer { Name = name, Type = type, DataRaw = "10 alias.example" }
                };
            } else if (name == $"_{port}._tcp.target.example" && type == DnsRecordType.TLSA) {
                response.Answers = new[] {
                    new DnsAnswer { Name = name, Type = type, DataRaw = "3 1 1 " + new string('A', 64) }
                };
            }
            typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                .SetValue(response, DnsSecValidationStatus.Secure);
            return Task.FromResult(response);
        };

        switch (route) {
            case "services":
                await check.VerifyDANE(new[] { new ServiceDefinition("alias.example", port) });
                break;
            case "https":
                await check.VerifyDANE("alias.example", new[] { ServiceType.HTTPS });
                break;
            case "smtp-mx":
                await check.VerifyDANE("example.com", new[] { ServiceType.SMTP });
                break;
            default:
                await check.VerifyDANE("alias.example", new[] { port });
                break;
        }

        Assert.Equal($"_{port}._tcp.target.example", Assert.Single(check.DaneAnalysis.QueriedNames));
        Assert.Single(check.DaneAnalysis.AnalysisResults);
        Assert.Equal(new[] { "target.example" }, evidenceHosts);
    }

    [Theory]
    [InlineData("target-absent", "_443._tcp.target.example,_443._tcp.alias.example")]
    [InlineData("insecure", "_443._tcp.alias.example")]
    [InlineData("loop", "_443._tcp.alias.example")]
    public async Task MissingOrUntrustedTargetUsesOriginalTlsaBase(string scenario, string expectedQueries) {
        using var check = new DomainHealthCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(null);
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            var response = new DnsResponse { Status = DnsResponseCode.NoError };
            if (type == DnsRecordType.CNAME && name == "alias.example") {
                response.Answers = new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "target.example" } };
            } else if (type == DnsRecordType.CNAME && name == "target.example" && scenario == "loop") {
                response.Answers = new[] { new DnsAnswer { Name = name, Type = type, DataRaw = "alias.example" } };
            } else if (type == DnsRecordType.TLSA && name == "_443._tcp.alias.example") {
                response.Answers = new[] {
                    new DnsAnswer { Name = name, Type = type, DataRaw = "3 1 1 " + new string('A', 64) }
                };
            }
            typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                .SetValue(response, scenario == "insecure" ? DnsSecValidationStatus.Insecure : DnsSecValidationStatus.Secure);
            return Task.FromResult(response);
        };

        await check.VerifyDANE("alias.example", new[] { 443 });

        Assert.Equal(expectedQueries.Split(','), check.DaneAnalysis.QueriedNames);
        Assert.Equal("_443._tcp.alias.example", Assert.Single(check.DaneAnalysis.AnalysisResults).DomainName);
    }
}
