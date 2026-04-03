using DomainDetective.Toolbox.Models;
using DomainDetective.Toolbox.Services;

namespace DomainDetective.Website.Tests;

public sealed class ToolPlannerPresentationTests {
    [Fact]
    public void BuildCatalogUrlReturnsToolsRootWhenDomainIsMissing() {
        var url = ToolPlannerPresentation.BuildCatalogUrl("   ");

        Assert.Equal("/tools/", url);
    }

    [Fact]
    public void BuildCatalogUrlTrimsAndEscapesDomain() {
        var url = ToolPlannerPresentation.BuildCatalogUrl(" contoso example.com ");

        Assert.Equal("/tools/?q=contoso%20example.com", url);
    }

    [Fact]
    public void BuildToolUrlAppendsDomainQuery() {
        var tool = CreateTool("spf");

        var url = ToolPlannerPresentation.BuildToolUrl(tool, "contoso.com");

        Assert.Equal("/tools/spf/?q=contoso.com", url);
    }

    [Fact]
    public void GetModeDistinguishesAvailableAdaptiveAndGuidedLocallyInStaticMode() {
        var available = CreateTool("spf", browserCompatible: true);
        var adaptive = CreateTool("mta-sts", browserCompatible: false, hostedCompatible: true, liteCompatible: true);
        var guided = CreateTool("ct-subdomains", browserCompatible: false, hostedCompatible: true);

        Assert.Equal(ToolPlannerMode.AvailableNow, ToolPlannerPresentation.GetMode(available, ToolsDeploymentMode.StaticOnly));
        Assert.Equal(ToolPlannerMode.Adaptive, ToolPlannerPresentation.GetMode(adaptive, ToolsDeploymentMode.StaticOnly));
        Assert.Equal(ToolPlannerMode.GuidedLocally, ToolPlannerPresentation.GetMode(guided, ToolsDeploymentMode.StaticOnly));
    }

    [Fact]
    public void CountToolsByModeUsesSharedPlannerRules() {
        var tools = new[] {
            CreateTool("spf", browserCompatible: true),
            CreateTool("dkim", browserCompatible: true),
            CreateTool("mta-sts", browserCompatible: false, hostedCompatible: true, liteCompatible: true),
            CreateTool("ct-subdomains", browserCompatible: false, hostedCompatible: true)
        };

        Assert.Equal(2, ToolPlannerPresentation.CountToolsByMode(tools, ToolsDeploymentMode.StaticOnly, ToolPlannerMode.AvailableNow));
        Assert.Equal(1, ToolPlannerPresentation.CountToolsByMode(tools, ToolsDeploymentMode.StaticOnly, ToolPlannerMode.Adaptive));
        Assert.Equal(1, ToolPlannerPresentation.CountToolsByMode(tools, ToolsDeploymentMode.StaticOnly, ToolPlannerMode.GuidedLocally));
    }

    [Fact]
    public void GetModeLabelReturnsGuidedLocallyForHostedOnlyTool() {
        var tool = CreateTool("rdap", browserCompatible: false, hostedCompatible: true);

        var label = ToolPlannerPresentation.GetModeLabel(tool, ToolsDeploymentMode.StaticOnly);

        Assert.Equal("Guided locally", label);
    }

    private static ToolDefinition CreateTool(string slug, bool browserCompatible = true, bool hostedCompatible = false, bool liteCompatible = false) {
        return new ToolDefinition {
            Name = slug,
            Slug = slug,
            Description = $"{slug} description",
            Category = ToolCategory.Dns,
            Icon = "globe",
            BrowserCompatible = browserCompatible,
            HostedCompatible = hostedCompatible,
            LiteCompatible = liteCompatible,
            InputPlaceholder = "example.com"
        };
    }
}
