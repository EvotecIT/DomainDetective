using DomainDetective.Toolbox.Components.Tools.EmailSecurity;

namespace DomainDetective.Website.Tests;

public sealed class MxEvidenceComponentTests : BunitContext {
    [Fact]
    public void IncompleteMxEvidenceIsNeutralRatherThanCountedAsPassing() {
        using var health = new DomainHealthCheck();
        // These are real analysis outcomes; the fixture avoids live authoritative socket probes.
        foreach (var property in new[] { "MxRecordExists", "MxRrsetComparisonIncomplete", "TargetAddressComparisonIncomplete", "CnameQueryFailed", "AddressQueryFailed" }) {
            typeof(MXAnalysis).GetProperty(property)!.SetValue(health.MXAnalysis, true);
        }

        var cut = Render<MxTool>(parameters => parameters
            .Add(component => component.HealthCheck, health)
            .Add(component => component.Domain, "example.com"));

        Assert.Equal("Info", cut.Find(".result-card-header .status-badge").TextContent.Trim());
        foreach (var label in new[] { "Valid MX configuration", "MX consistent across nameservers", "Addresses consistent across nameservers", "No MX pointing to a CNAME", "All MX targets exist", "All MX targets have A/AAAA" }) {
            Assert.Contains(label, cut.Find(".result-checklist-facts").TextContent);
            Assert.DoesNotContain(label, cut.Find(".result-checklist-passed").TextContent);
        }
    }

    [Theory]
    [InlineData("PointsToCname", "No MX pointing to a CNAME")]
    [InlineData("PointsToNonExistentDomain", "All MX targets exist")]
    [InlineData("PointsToDomainWithoutAOrAaaaRecord", "All MX targets have A/AAAA")]
    public void FailedSiblingQueriesDoNotHideObservedConfigurationDefects(string property, string label) {
        using var health = new DomainHealthCheck();
        foreach (var flag in new[] { "MxRecordExists", "CnameQueryFailed", "AddressQueryFailed", property }) {
            typeof(MXAnalysis).GetProperty(flag)!.SetValue(health.MXAnalysis, true);
        }

        var cut = Render<MxTool>(parameters => parameters
            .Add(component => component.HealthCheck, health)
            .Add(component => component.Domain, "example.com"));

        var problems = cut.Find(".result-checklist-problems").TextContent;
        Assert.Contains(label, problems);
        Assert.Contains("Valid MX configuration", problems);
    }

    [Fact]
    public void FailedThirdServerDoesNotHideObservedAuthoritativeDisagreement() {
        using var health = new DomainHealthCheck();
        foreach (var property in new[] { "MxRrsetComparisonIncomplete", "TargetAddressComparisonIncomplete" }) {
            typeof(MXAnalysis).GetProperty(property)!.SetValue(health.MXAnalysis, true);
        }
        foreach (var property in new[] { "MxRrsetConsistentAcrossNs", "TargetAddressConsistentAcrossNs" }) {
            typeof(MXAnalysis).GetProperty(property)!.SetValue(health.MXAnalysis, false);
        }

        var cut = Render<MxTool>(parameters => parameters
            .Add(component => component.HealthCheck, health)
            .Add(component => component.Domain, "example.com"));

        var problems = cut.Find(".result-checklist-problems").TextContent;
        Assert.Contains("MX consistent across nameservers", problems);
        Assert.Contains("Addresses consistent across nameservers", problems);
    }
}
