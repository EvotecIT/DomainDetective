using DnsClientX;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

    [Fact]
    public async Task AliasLoopRemainsAQueryFailure() {
        using var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            Assert.Equal(DnsRecordType.CNAME, type);
            var response = new DnsResponse {
                Status = DnsResponseCode.NoError,
                Answers = new[] { new DnsAnswer { Name = name, Type = type,
                    DataRaw = name == "alias.example" ? "target.example" : "alias.example" } }
            };
            typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!
                .SetValue(response, DnsSecValidationStatus.Secure);
            return Task.FromResult(response);
        };

        await check.VerifyDANE("alias.example", new[] { 443 });

        Assert.True(check.DaneAnalysis.DnsQueryFailed);
        Assert.Empty(check.DaneAnalysis.QueriedNames);
        Assert.Empty(check.DaneAnalysis.AnalysisResults);
        Assert.DoesNotContain(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
    }

    [Theory]
    [InlineData(DnsSecValidationStatus.Secure, false)]
    [InlineData(DnsSecValidationStatus.Insecure, true)]
    public async Task OriginalTlsaAuthenticatesWhenTargetHasNoSecureTlsa(DnsSecValidationStatus targetStatus, bool targetHasRecord) {
        using var certificate = CreateCertificate();
        string digest;
        using (var sha = SHA256.Create()) {
            digest = BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", string.Empty);
        }
        using var check = new DomainHealthCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence {
            EndEntityCertificate = certificate,
            DnssecValidated = true
        });
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            if (type == DnsRecordType.CNAME && name == "alias.example") {
                return Task.FromResult(Response(DnsSecValidationStatus.Secure,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "target.example" }));
            }
            if (type == DnsRecordType.TLSA && name == "_443._tcp.target.example") {
                return Task.FromResult(Response(targetStatus, targetHasRecord
                    ? new DnsAnswer { Name = name, Type = type, DataRaw = "3 0 1 " + new string('0', 64) }
                    : null));
            }
            if (type == DnsRecordType.TLSA && name == "_443._tcp.alias.example") {
                return Task.FromResult(Response(DnsSecValidationStatus.Secure,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "3 0 1 " + digest }));
            }
            return Task.FromResult(Response(DnsSecValidationStatus.Secure));
        };

        await check.VerifyDANE("alias.example", new[] { 443 });

        Assert.Equal(new[] { "_443._tcp.target.example", "_443._tcp.alias.example" }, check.DaneAnalysis.QueriedNames);
        var record = Assert.Single(check.DaneAnalysis.AnalysisResults);
        Assert.Equal("_443._tcp.alias.example", record.DomainName);
        Assert.Equal(DaneAuthenticationStatus.Authenticated, record.AuthenticationStatus);
        Assert.True(check.DaneAnalysis.AllServicesAuthenticated);
        Assert.False(check.DaneAnalysis.DnsQueryFailed);
    }

    [Theory]
    [InlineData(DnsResponseCode.ServerFailure, DnsSecValidationStatus.NotRequested)]
    [InlineData(DnsResponseCode.NoError, DnsSecValidationStatus.Bogus)]
    [InlineData(DnsResponseCode.NoError, DnsSecValidationStatus.Indeterminate)]
    public async Task FailedAliasLookupDoesNotBecomeTlsaAbsence(DnsResponseCode status, DnsSecValidationStatus validation) {
        using var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            Assert.Equal("alias.example", name);
            Assert.Equal(DnsRecordType.CNAME, type);
            return Task.FromResult(Response(validation, status: status));
        };

        await check.VerifyDANE("alias.example", new[] { 443 });

        Assert.True(check.DaneAnalysis.DnsQueryFailed);
        Assert.False(check.DaneAnalysis.AllServicesAuthenticated);
        Assert.Empty(check.DaneAnalysis.QueriedNames);
        Assert.DoesNotContain(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
    }

    [Theory]
    [InlineData(DnsSecValidationStatus.Bogus)]
    [InlineData(DnsSecValidationStatus.Indeterminate)]
    [InlineData(DnsSecValidationStatus.NotRequested)]
    public async Task UnverifiableTargetTlsaDoesNotFallBackAsIfAbsent(DnsSecValidationStatus validation) {
        using var check = new DomainHealthCheck();
        var queries = new List<string>();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            queries.Add(name);
            if (type == DnsRecordType.CNAME && name == "alias.example") {
                return Task.FromResult(Response(DnsSecValidationStatus.Secure,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "target.example" }));
            }
            if (type == DnsRecordType.TLSA && name == "_443._tcp.target.example") {
                return Task.FromResult(Response(validation));
            }
            return Task.FromResult(Response(DnsSecValidationStatus.Secure));
        };

        await check.VerifyDANE("alias.example", new[] { 443 });

        Assert.Equal(new[] { "alias.example", "target.example", "_443._tcp.target.example" }, queries);
        Assert.True(check.DaneAnalysis.DnsQueryFailed);
        Assert.False(check.DaneAnalysis.AllServicesAuthenticated);
        Assert.DoesNotContain(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
    }

    [Fact]
    public async Task UnverifiableOriginalTlsaDoesNotClaimAbsence() {
        using var check = new DomainHealthCheck();
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) =>
            Task.FromResult(Response(type == DnsRecordType.CNAME
                ? DnsSecValidationStatus.Secure : DnsSecValidationStatus.NotRequested));

        await check.VerifyDANE("example.com", new[] { 443 });

        Assert.True(check.DaneAnalysis.DnsQueryFailed);
        Assert.DoesNotContain(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.NoRecords);
    }

    [Fact]
    public async Task InsecureMxCannotAuthenticateRequestedDomain() {
        using var certificate = CreateCertificate();
        string digest;
        using (var sha = SHA256.Create()) {
            digest = BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", string.Empty);
        }
        using var check = new DomainHealthCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(new DaneCertificateEvidence {
            EndEntityCertificate = certificate,
            DnssecValidated = true
        });
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            if (type == DnsRecordType.MX) {
                return Task.FromResult(Response(DnsSecValidationStatus.Insecure,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "10 attacker.example" }));
            }
            if (type == DnsRecordType.TLSA) {
                return Task.FromResult(Response(DnsSecValidationStatus.Secure,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "3 0 1 " + digest }));
            }
            return Task.FromResult(Response(DnsSecValidationStatus.Secure));
        };

        await check.VerifyDANE("example.com", new[] { ServiceType.SMTP });

        Assert.Equal(DaneAuthenticationStatus.Authenticated, Assert.Single(check.DaneAnalysis.AnalysisResults).AuthenticationStatus);
        Assert.False(check.DaneAnalysis.MxDnssecValidated);
        Assert.False(check.DaneAnalysis.AllServicesAuthenticated);
        Assert.False(DomainDetective.Views.Converters.Convert(check.DaneAnalysis).AllServicesAuthenticated);
        Assert.Contains(check.DaneAnalysis.Assessments, assessment => assessment.Code == DaneCodes.MxNotAuthenticated);
        Assert.Contains(DomainDetective.Narratives.DaneNarrative.Build(check.DaneAnalysis).Highlights,
            highlight => highlight.StartsWith("MX service selection was not DNSSEC authenticated"));
    }

    [Theory]
    [InlineData(DnsSecValidationStatus.Secure, DnsSecValidationStatus.Secure, true)]
    [InlineData(DnsSecValidationStatus.Insecure, DnsSecValidationStatus.Secure, false)]
    [InlineData(DnsSecValidationStatus.Secure, DnsSecValidationStatus.Insecure, false)]
    public async Task MailClassifierCountsOnlySecureMxAndTlsa(
        DnsSecValidationStatus mxStatus, DnsSecValidationStatus tlsaStatus, bool expected) {
        using var check = new DomainHealthCheck();
        check.DaneCertificateEvidenceOverride = (_, _, _) => Task.FromResult<DaneCertificateEvidence?>(null);
        check.DnsConfiguration.QueryDnsResponseOverride = (name, type, _) => {
            if (type == DnsRecordType.MX) {
                return Task.FromResult(Response(mxStatus,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "10 mx.example.com" }));
            }
            if (type == DnsRecordType.TLSA) {
                return Task.FromResult(Response(tlsaStatus,
                    new DnsAnswer { Name = name, Type = type, DataRaw = "3 1 1 " + new string('A', 64) }));
            }
            return Task.FromResult(Response(DnsSecValidationStatus.Secure));
        };

        var classifier = new MailDomainClassifier(check, new InternalLogger(false));
        var result = await classifier.ClassifyAsync("example.com");

        Assert.Equal(expected, result.Signals.HasDANE);
        Assert.Equal(expected, check.DaneAnalysis.HasSecureTlsaRecords && check.DaneAnalysis.MxDnssecValidated == true);
    }

    private static DnsResponse Response(DnsSecValidationStatus validation, DnsAnswer? answer = null,
        DnsResponseCode status = DnsResponseCode.NoError) {
        var response = new DnsResponse {
            Status = status,
            Answers = answer == null ? Array.Empty<DnsAnswer>() : new[] { answer.Value }
        };
        typeof(DnsResponse).GetProperty(nameof(DnsResponse.DnsSecValidationStatus))!.SetValue(response, validation);
        return response;
    }

    private static X509Certificate2 CreateCertificate() {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }
}
