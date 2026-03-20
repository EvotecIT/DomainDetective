using System;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestDomainVerificationSupport
{
    [Theory]
    [InlineData(HealthCheckType.ARC, false)]
    [InlineData(HealthCheckType.SMIMEA, false)]
    [InlineData(HealthCheckType.WHOIS, true)]
    [InlineData(HealthCheckType.WEBSITE, true)]
    [InlineData(HealthCheckType.SPFFLATTENED, true)]
    [InlineData(HealthCheckType.MAILCLASSIFICATION, true)]
    [InlineData(HealthCheckType.NTP, true)]
    public void SupportsDomainVerification_ReturnsExpectedValue(HealthCheckType healthCheckType, bool expected)
    {
        Assert.Equal(expected, DomainHealthCheck.SupportsDomainVerification(healthCheckType));
    }

    [Fact]
    public async Task Verify_RejectsChecksThatNeedSpecializedInput()
    {
        var healthCheck = new DomainHealthCheck();

        var ex = await Assert.ThrowsAsync<ArgumentException>(() =>
            healthCheck.Verify("example.com", new[] { HealthCheckType.ARC, HealthCheckType.SMIMEA }));

        Assert.Contains(nameof(HealthCheckType.ARC), ex.Message);
        Assert.Contains(nameof(HealthCheckType.SMIMEA), ex.Message);
    }
}
