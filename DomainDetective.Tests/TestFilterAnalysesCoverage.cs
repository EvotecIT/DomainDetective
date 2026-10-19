using System.Reflection;

namespace DomainDetective.Tests;

public class TestFilterAnalysesCoverage
{
    [Fact]
    public async Task FilteredPartialRunRetainsFailureCompletionAndSupplementalEvidence() {
        using var health = new DomainHealthCheck();
        health.ExecutionOptions.IncludeTakeoverCname = true;
        health.DnsConfiguration.QueryDnsResponseOverride = (_, type, _) => type == DnsClientX.DnsRecordType.SOA
            ? throw new InvalidOperationException("Synthetic SOA failure")
            : Task.FromResult(new DnsClientX.DnsResponse { Status = DnsClientX.DnsResponseCode.NoError });
        await Assert.ThrowsAsync<InvalidOperationException>(() => health.Verify("fixture.example",
            new[] { HealthCheckType.CAA, HealthCheckType.SOA },
            executionOptions: new HealthCheckExecutionOptions { EnableParallelism = false, IncludeTakeoverCname = true }));
        using var filtered = health.FilterAnalyses(new[] { HealthCheckType.CAA, HealthCheckType.SOA });
        Assert.False(filtered.VerificationCompleted);
        Assert.Equal(health.VerificationError, filtered.VerificationError);
        Assert.Equal(health.VerificationRequestedChecks, filtered.VerificationRequestedChecks);
        Assert.Equal(health.VerificationCompletedChecks, filtered.VerificationCompletedChecks);
        Assert.True(filtered.VerificationTakeoverCompleted);
        Assert.NotSame(health.TakeoverCnameAnalysis, filtered.TakeoverCnameAnalysis);
        using var json = System.Text.Json.JsonDocument.Parse(filtered.ToJson());
        Assert.False(json.RootElement.GetProperty("VerificationCompleted").GetBoolean());
        await health.Verify("fixture.example", new[] { HealthCheckType.CAA });
        Assert.True(health.VerificationCompleted);
        Assert.False(filtered.VerificationCompleted);
        Assert.Contains(HealthCheckType.SOA, filtered.VerificationRequestedChecks);
    }

    [Fact]
    public void FilterAnalyses_RetainsPreviouslyDroppedSelections()
    {
        var healthCheck = new DomainHealthCheck();
        var classificationProperty = typeof(DomainHealthCheck).GetProperty(
            nameof(DomainHealthCheck.MailDomainClassification),
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)!;
        classificationProperty.SetValue(healthCheck, new MailDomainClassificationResult { Domain = "example.com" });

        var selected = new[]
        {
            HealthCheckType.SMIMEA,
            HealthCheckType.ROBOTS,
            HealthCheckType.WHOIS,
            HealthCheckType.RDAP,
            HealthCheckType.DNSHEALTH,
            HealthCheckType.APEXADDRESS,
            HealthCheckType.IPENRICHMENT,
            HealthCheckType.SUBDOMAINS,
            HealthCheckType.DNSINVENTORY,
            HealthCheckType.DNSTRACE,
            HealthCheckType.CTTIMELINE,
            HealthCheckType.DNSPROPAGATION,
            HealthCheckType.MAILCLASSIFICATION,
            HealthCheckType.SPFFLATTENED,
            HealthCheckType.WEBSITE
        };

        var filtered = healthCheck.FilterAnalyses(selected);
        var map = filtered.GetAnalysisMap();

        foreach (var healthCheckType in selected)
        {
            Assert.True(map.TryGetValue(healthCheckType, out var value));
            Assert.NotNull(value);
        }
    }
}
