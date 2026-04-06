using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Models;

namespace DomainDetective.Website.Tests;

public sealed class ToolCategoryGridComponentTests : TestContext {
    [Fact]
    public void UsesSimpleToolLinksAndAvailabilityDotsInStaticMode() {
        var tools = new[] {
            CreateTool("dns-lookup", ToolCategory.Dns, browserCompatible: true),
            CreateTool("mx-lookup", ToolCategory.EmailSecurity, browserCompatible: false, liteCompatible: true),
            CreateTool("ct-subdomains", ToolCategory.Subdomain, browserCompatible: false, hostedCompatible: true)
        };

        var cut = RenderComponent<ToolCategoryGrid>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly));

        var links = cut.FindAll("a.category-tool-link");
        Assert.Contains(links, link => link.GetAttribute("href") == "/tools/dns-lookup/");
        Assert.Contains(links, link => link.GetAttribute("href") == "/tools/mx-lookup/");
        Assert.Contains(links, link => link.GetAttribute("href") == "/tools/ct-subdomains/");

        Assert.Contains("tool-availability-dot-browser", cut.Markup);
        Assert.Contains("tool-availability-dot-partial", cut.Markup);
        Assert.Contains("tool-availability-dot-local", cut.Markup);
        Assert.DoesNotContain("Guided locally", cut.Markup);
        Assert.DoesNotContain("Adaptive", cut.Markup);
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
