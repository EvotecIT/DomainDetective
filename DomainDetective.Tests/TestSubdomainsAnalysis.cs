using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestSubdomainsAnalysis
{
    [Fact]
    public async Task ParsesCtAndAggregatesSubdomains()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""a.example.com\nb.example.com\n*.wild.example.com\nexample.com"" },
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-02-01T00:00:00Z"", ""name_value"": ""a.example.com\nc.example.com"" },
  { ""issuer_name"": ""Issuer B"", ""entry_timestamp"": ""2019-12-31T00:00:00Z"", ""name_value"": ""d.example.com"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (_, _) => Task.FromResult(json)
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(3, analysis.CertificateObservationCount);
        Assert.Equal(new DateTimeOffset(2019, 12, 31, 0, 0, 0, TimeSpan.Zero), analysis.FirstSeenUtc);
        Assert.Equal(new DateTimeOffset(2020, 2, 1, 0, 0, 0, TimeSpan.Zero), analysis.LastSeenUtc);

        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer A", out var aCount));
        Assert.True(analysis.IssuerCounts.TryGetValue("Issuer B", out var bCount));
        Assert.Equal(2, aCount);
        Assert.Equal(1, bCount);

        var names = analysis.Subdomains.Select(s => s.Name).ToList();
        Assert.Contains("a.example.com", names);
        Assert.Contains("b.example.com", names);
        Assert.Contains("c.example.com", names);
        Assert.Contains("d.example.com", names);
        Assert.Contains("wild.example.com", names);
        Assert.DoesNotContain("example.com", names);

        var a = analysis.Subdomains.Single(s => s.Name == "a.example.com");
        Assert.Equal(new DateTimeOffset(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), a.FirstSeenUtc);
        Assert.Equal(new DateTimeOffset(2020, 2, 1, 0, 0, 0, TimeSpan.Zero), a.LastSeenUtc);
    }

    [Fact]
    public async Task DnsVerificationCappedSetsResolutionReduced()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""x.example.com\ny.example.com\nz.example.com"" }
]";

        var seen = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = true,
            MaxResolutionChecks = 2,
            ResolutionConcurrency = 2,
            QueryOverride = (_, _) => Task.FromResult(json),
            DnsConfiguration = new DnsConfiguration
            {
                QueryDnsOverride = (name, type) =>
                {
                    var key = name + "|" + type;
                    seen[key] = seen.TryGetValue(key, out var c) ? c + 1 : 1;

                    if (name.Equals("x.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.1" } });
                    }
                    if (name.Equals("y.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.AAAA)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.AAAA, DataRaw = "2001:db8::1" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.True(analysis.ResolutionReduced);

        var x = analysis.Subdomains.Single(s => s.Name == "x.example.com");
        var y = analysis.Subdomains.Single(s => s.Name == "y.example.com");
        var z = analysis.Subdomains.Single(s => s.Name == "z.example.com");

        Assert.Equal(SubdomainResolutionStatus.Resolves, x.ResolutionStatus);
        Assert.Equal(SubdomainResolutionStatus.Resolves, y.ResolutionStatus);
        Assert.Equal(SubdomainResolutionStatus.Unknown, z.ResolutionStatus);

        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.ResolutionReduced);

        Assert.Contains(seen.Keys, k => k.StartsWith("x.example.com|", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(seen.Keys, k => k.StartsWith("y.example.com|", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(seen.Keys, k => k.StartsWith("z.example.com|", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task NonArrayCtResponseProducesNoResultsAssessment()
    {
        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (_, _) => Task.FromResult(@"{ ""ok"": true }")
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Empty(analysis.Subdomains);
        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.CtNoResults);
    }

    [Fact]
    public async Task AiInfrastructureExposureProducesAssessmentWhenEnabled()
    {
        const string json = @"
[
  { ""issuer_name"": ""Issuer A"", ""entry_timestamp"": ""2020-01-01T00:00:00Z"", ""name_value"": ""mlflow.example.com"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = true,
            DetectAiInfrastructureExposure = true,
            MaxResolutionChecks = 10,
            ResolutionConcurrency = 2,
            QueryOverride = (_, _) => Task.FromResult(json),
            DnsConfiguration = new DnsConfiguration
            {
                QueryDnsOverride = (name, type) =>
                {
                    if (name.Equals("mlflow.example.com", StringComparison.OrdinalIgnoreCase) && type == DnsRecordType.A)
                    {
                        return Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.A, DataRaw = "192.0.2.1" } });
                    }
                    return Task.FromResult(Array.Empty<DnsAnswer>());
                }
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.Contains(analysis.Assessments, a => a.Code == SubdomainCodes.AiInfrastructureExposed);
    }

    [Fact]
    public async Task FallsBackToCertSpotterWhenCrtShFails()
    {
        const string certSpotterJson = @"
[
  { ""id"": ""12345"", ""dns_names"": [""api.example.com"", ""example.com""], ""not_before"": ""2026-01-01T00:00:00Z"", ""not_after"": ""2027-01-01T00:00:00Z"" }
]";

        var analysis = new SubdomainsAnalysis
        {
            VerifyStillResolves = false,
            QueryOverride = (url, _) =>
            {
                if (url.Contains("crt.sh", StringComparison.OrdinalIgnoreCase))
                {
                    throw new HttpRequestException("Simulated crt.sh outage.");
                }

                return Task.FromResult(certSpotterJson);
            }
        };

        await analysis.AnalyzeAsync("example.com", new InternalLogger(), CancellationToken.None);

        Assert.True(analysis.QuerySucceeded);
        Assert.Equal(1, analysis.CertificateObservationCount);
        Assert.Contains(analysis.Subdomains, s => s.Name == "api.example.com");
        Assert.DoesNotContain(analysis.Subdomains, s => s.Name == "example.com");
        Assert.DoesNotContain(analysis.Assessments, a => a.Code == SubdomainCodes.CtQueryFailed);
    }
}
