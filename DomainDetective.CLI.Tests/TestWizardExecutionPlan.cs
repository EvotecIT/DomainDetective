using DomainDetective.CLI.Wizard;

namespace DomainDetective.CLI.Tests;

public class TestWizardExecutionPlan {
    [Theory]
    [InlineData(ScanMode.Quick)]
    [InlineData(ScanMode.Default)]
    [InlineData(ScanMode.Full)]
    public void ExplicitWizardChecksAllReachThePlanRegardlessOfPreset(ScanMode mode) {
        var selected = new[] { HealthCheckType.SITEMAP, HealthCheckType.HTTP, HealthCheckType.DNSBL,
            HealthCheckType.TTL, HealthCheckType.CAA, HealthCheckType.HTTP };
        var plan = DomainWizard.BuildPlan(new WizardOptions { Domain = "example.com", Mode = mode, Checks = selected });
        Assert.Equal(selected.Distinct().OrderBy(value => value), plan.Checks.OrderBy(value => value));
        Assert.Contains(plan.Stages, stage => stage.Enabled && stage.Types.Contains(HealthCheckType.SITEMAP));
        Assert.Contains(plan.Stages, stage => stage.Enabled && stage.Types.Contains(HealthCheckType.DNSBL));
        Assert.DoesNotContain(HealthCheckType.WHOIS, plan.Checks);
    }

    [Fact]
    public void WizardPresetRetainsItsDefaultCoverageAndFullReputationChecks() {
        var quick = DomainWizard.BuildPlan(new WizardOptions { Domain = "example.com", Mode = ScanMode.Quick });
        var full = DomainWizard.BuildPlan(new WizardOptions { Domain = "example.com", Mode = ScanMode.Full });
        Assert.Contains(HealthCheckType.TTL, quick.Checks);
        Assert.Contains(HealthCheckType.MX, quick.Checks);
        Assert.DoesNotContain(HealthCheckType.HTTP, quick.Checks);
        Assert.DoesNotContain(HealthCheckType.DNSBL, quick.Checks);
        Assert.Contains(HealthCheckType.HTTP, full.Checks);
        Assert.Contains(HealthCheckType.CERT, full.Checks);
        Assert.Contains(HealthCheckType.DANE, full.Checks);
        Assert.Contains(HealthCheckType.DNSBL, full.Checks);
        Assert.Contains(HealthCheckType.RPKI, full.Checks);
        Assert.Contains(HealthCheckType.WHOIS, full.Checks);
    }
}
