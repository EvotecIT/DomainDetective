using Xunit;

namespace DomainDetective.Tests;

public class TestGetAnalysisMap
{
    [Fact]
    public void ReturnsDictionaryWithAllAnalyses()
    {
        var healthCheck = new DomainHealthCheck();
        var map = healthCheck.GetAnalysisMap();

        Assert.Equal(Enum.GetValues<HealthCheckType>().Length, map.Count);
        Assert.Same(healthCheck.DmarcAnalysis, map[HealthCheckType.DMARC]);
        Assert.Same(healthCheck.SpfAnalysis, map[HealthCheckType.SPF]);
        Assert.Same(healthCheck.DKIMAnalysis, map[HealthCheckType.DKIM]);
    }
}
