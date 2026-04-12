using DomainDetective.Toolbox.Models;
using DomainDetective.Toolbox.Services;

namespace DomainDetective.Website.Tests;

public sealed class ToolCapabilityPresentationTests {
    [Fact]
    public void BuildDescribesM365StaticCoverageAsPartialBrowserSupport() {
        var tool = CreateTool("m365-overview", ToolCategory.Overview, browserCompatible: false, hostedCompatible: true, liteCompatible: true);

        var capability = ToolCapabilityPresentation.Build(tool, ToolsDeploymentMode.StaticOnly);

        Assert.Equal("Partial browser support", capability.Title);
        Assert.Contains(capability.BrowserChecks, item => item.Contains("Microsoft mail provider", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(capability.DeeperChecks, item => item.Contains("Tenant identity", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildDescribesHostedOnlyStaticCoverageAsGuidedLocally() {
        var tool = CreateTool("cert-check", ToolCategory.TlsCert, browserCompatible: false, hostedCompatible: true);

        var capability = ToolCapabilityPresentation.Build(tool, ToolsDeploymentMode.StaticOnly);

        Assert.Equal("Guided locally", capability.Title);
        Assert.Contains("GitHub Pages browser edition", capability.Description, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(capability.DeeperChecks, item => item.Contains("CLI", StringComparison.OrdinalIgnoreCase));
    }

    private static ToolDefinition CreateTool(string slug, ToolCategory category, bool browserCompatible, bool hostedCompatible = false, bool liteCompatible = false) {
        return new ToolDefinition {
            Name = slug,
            Slug = slug,
            Description = $"{slug} description",
            Category = category,
            Icon = "globe",
            BrowserCompatible = browserCompatible,
            HostedCompatible = hostedCompatible,
            LiteCompatible = liteCompatible,
            InputPlaceholder = "example.com"
        };
    }
}
