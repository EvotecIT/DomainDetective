using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Models;

namespace DomainDetective.Website.Tests;

public sealed class ToolCategoryGridComponentTests : TestContext {
    [Fact]
    public void ShowsStaticOnlyAvailabilityDotForHostedOnlyTools() {
        var tools = new[] {
            CreateTool("ct-subdomains", ToolCategory.Subdomain, browserCompatible: false, hostedCompatible: true)
        };

        var cut = RenderComponent<ToolCategoryGrid>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly));

        var link = cut.Find("a.category-tool-link");
        var dot = cut.Find(".tool-availability-dot");

        Assert.Equal("/tools/ct-subdomains/", link.GetAttribute("href"));
        Assert.Contains("tool-availability-dot-local", dot.ClassName);
        Assert.Contains("ct-subdomains", link.TextContent);
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
