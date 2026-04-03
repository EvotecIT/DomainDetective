using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Models;

namespace DomainDetective.Website.Tests;

public sealed class ToolCategoryGridComponentTests : TestContext {
    [Fact]
    public void PreservesDomainAndGuidedLocallyBadgeForHostedOnlyTools() {
        var tools = new[] {
            CreateTool("ct-subdomains", ToolCategory.Subdomain, browserCompatible: false, hostedCompatible: true)
        };

        var cut = RenderComponent<ToolCategoryGrid>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly)
            .Add(component => component.CurrentDomain, "contoso.com"));

        var link = cut.Find("a.category-tool-link");
        Assert.Equal("/tools/ct-subdomains/?q=contoso.com", link.GetAttribute("href"));
        Assert.Contains("Guided locally", link.TextContent);
    }

    private static ToolDefinition CreateTool(string slug, ToolCategory category, bool browserCompatible = true, bool hostedCompatible = false, bool liteCompatible = false) {
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
