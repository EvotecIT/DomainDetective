using DnsClientX;
using DomainDetective.Views;
using DomainDetective.Reports;
namespace DomainDetective.Tests;
public class TestAssessmentFailureIntegration {
    private static DomainHealthCheck Create() {
        var health = new DomainHealthCheck();
        health.DnsConfiguration.QueryDnsOverride = (_, type) => Task.FromResult(type == DnsRecordType.CAA
            ? new[] { new DnsAnswer { Type = type, DataRaw = "0 issue \"ca.example.test\"" } } : Array.Empty<DnsAnswer>());
        return health;
    }
    [Theory]
    [InlineData(HealthCheckType.DMARC)]
    [InlineData(HealthCheckType.EDNSSUPPORT)]
    public async Task FailureEvidenceRetainsCheckIdentityInAssessmentReports(HealthCheckType check) {
        using var health = Create();
        health.DmarcDiscoveryMode = DmarcDiscoveryMode.LegacyPublicSuffix;
        health.DnsConfiguration.QueryDnsOverride = (_, type) => type == DnsRecordType.TXT
            ? throw new TimeoutException("DMARC query failed.")
            : Task.FromResult(new[] { new DnsAnswer { Type = DnsRecordType.CAA, DataRaw = "0 issue \"letsencrypt.org\"" } });
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("EDNS discovery failed.");
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.com", new[] { check, HealthCheckType.CAA }));
        var report = DomainAssessmentBuilder.Build(Converters.ConvertChecks(health));
        var domain = Assert.Single(report.Domains);
        Assert.Equal(2, domain.Checks.Count);
        var failed = Assert.Single(domain.Checks, item => item.Check == check);
        Assert.Equal(1, failed.ErrorCount);
        Assert.Equal(Converters.AreaFor(check), failed.Area);
        Assert.Equal(1, domain.ErrorChecks);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DocumentOverviewCountsFailuresWhenSomeOrAllChecksFail(bool allFail) {
        using var health = Create();
        health.EdnsSupportAnalysis.QueryDnsOverride = (_, _) => throw new TimeoutException("EDNS discovery failed.");
        if (allFail) {
            health.DnsConfiguration.QueryDnsOverride = (_, _) => throw new TimeoutException("CAA query failed.");
        }
        await Assert.ThrowsAsync<TimeoutException>(() => health.Verify("example.com", new[] { HealthCheckType.EDNSSUPPORT, HealthCheckType.CAA }));
        var views = Converters.ConvertChecks(health).ToList();
        int expected = allFail ? 2 : 1;
        var row = Assert.Single(ExecutiveSummaryBuilder.Build(views, DomainOrder.Alphabetical));
        Assert.Equal("example.com", row.Domain);
        Assert.Equal(expected, row.Errors);
        Assert.Contains("1 domain", OverviewWording.ComposeFromItems(views));

        // Additional evidence may overlap a view's assessment; keep each finding once and preserve other findings.
        var extra = new Assessment { Severity = AssessmentSeverity.Error, Message = "Additional evidence" };
        views.Add(new AssessmentEvidenceInfo("example.com", health.Assessments.Concat(new[] { extra })));
        Assert.Equal(expected + 1, Assert.Single(ExecutiveSummaryBuilder.Build(views, DomainOrder.Alphabetical)).Errors);
    }


}
