using System.Threading.Tasks;
using DnsClientX;
using Xunit;

namespace DomainDetective.Tests;

public class TestDkimExplicitSelectorsMissing
{
    [Fact]
    public async Task ExplicitSelectors_DoNotEmitMissingByDefault()
    {
        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(internalLogger: logger);
        healthCheck.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());

        await healthCheck.VerifyDKIM("example.com", new[] { "s1" });

        Assert.Empty(healthCheck.DKIMAnalysis.AnalysisResults);
    }

    [Fact]
    public async Task ExplicitSelectors_EmitMissing_WhenRequested()
    {
        var logger = new InternalLogger(false);
        var healthCheck = new DomainHealthCheck(internalLogger: logger);
        healthCheck.DnsConfiguration.QueryDnsOverride = (_, _) => Task.FromResult(System.Array.Empty<DnsAnswer>());

        await healthCheck.VerifyDKIM("example.com", new[] { "s1" }, includeMissingSelectors: true);

        Assert.True(healthCheck.DKIMAnalysis.AnalysisResults.ContainsKey("s1"));
        var s1 = healthCheck.DKIMAnalysis.AnalysisResults["s1"];
        Assert.False(s1.DkimRecordExists);
        Assert.Equal("s1._domainkey.example.com", s1.Name);
        Assert.Contains(healthCheck.DKIMAnalysis.Assessments, a => a.Code == DkimCodes.RecordMissing);
    }
}

