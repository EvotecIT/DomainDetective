using Xunit;

namespace DomainDetective.Tests;

public class TestGetAnalysisMap
{
    [Fact]
    public void ReturnsDictionaryWithAllAnalyses()
    {
        var healthCheck = new DomainHealthCheck();
        var map = healthCheck.GetAnalysisMap();

        Assert.Equal(Enum.GetValues(typeof(HealthCheckType)).Length, map.Count);

        foreach (HealthCheckType type in Enum.GetValues(typeof(HealthCheckType)))
        {
            var prop = typeof(DomainHealthCheck).GetProperty($"{type}Analysis");
            var expected = prop?.GetValue(healthCheck);

            Assert.True(map.TryGetValue(type, out var actual));
            Assert.Same(expected, actual);
        }
    }
}
