using System.Reflection;

namespace DomainDetective.Tests;

public class TestFilterAnalysesCoverage
{
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
