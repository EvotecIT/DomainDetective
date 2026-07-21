using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Models;

namespace DomainDetective.Website.Tests;

public sealed class ToolLaunchPlannerComponentTests : BunitContext {
    [Fact]
    public void RendersStarterPlanSummaryAndPrimaryActionWithSelectedDomain() {
        var tools = CreatePlannerTools();

        var cut = Render<ToolLaunchPlanner>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.Domain, "contoso.com")
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly));

        var pills = cut.FindAll(".tool-plan-status-pill").Select(element => element.TextContent.Trim()).ToArray();
        Assert.Equal(new[] { "4 available now", "0 adaptive", "0 guided locally" }, pills);

        var primaryAction = cut.Find(".tool-plan-actions a.tool-run-btn");
        Assert.Equal("Open first selected tool", primaryAction.TextContent.Trim());
        Assert.Equal("/tools/spf/?q=contoso.com", primaryAction.GetAttribute("href"));
    }

    [Fact]
    public void RendersOverviewToolsAsSeparateQuickStartCards() {
        var tools = CreatePlannerTools();

        var cut = Render<ToolLaunchPlanner>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.Domain, "contoso.com")
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly));

        var overviewCards = cut.FindAll(".tool-plan-overview-card");
        Assert.Equal(2, overviewCards.Count);
        Assert.DoesNotContain(">Overview<", cut.Markup);
        Assert.Contains("/tools/domain-overview/?q=contoso.com", cut.Markup);
        Assert.Contains("/tools/m365-overview/?q=contoso.com", cut.Markup);
    }

    [Fact]
    public void SelectAllVisibleToolsShowsGuidedLocalSummaryAndLinks() {
        var tools = CreatePlannerTools();

        var cut = Render<ToolLaunchPlanner>(parameters => parameters
            .Add(component => component.Tools, tools)
            .Add(component => component.Domain, "contoso.com")
            .Add(component => component.DeploymentMode, ToolsDeploymentMode.StaticOnly));

        cut.FindAll("button")
            .Single(button => button.TextContent.Contains("Select all checks", StringComparison.Ordinal))
            .Click();

        Assert.Contains("1 guided locally", cut.Markup);
        Assert.Contains("Guided locally", cut.Markup);
        Assert.Contains("This run includes deeper checks that stay guided", cut.Markup);
        Assert.Contains("/tools/ct-subdomains/?q=contoso.com", cut.Markup);
        Assert.DoesNotContain("/tools/domain-overview/?q=contoso.com", cut.Find(".tool-plan-results").InnerHtml);
    }

    private static IReadOnlyList<ToolDefinition> CreatePlannerTools() {
        return new[] {
            CreateTool("m365-overview", ToolCategory.Overview, browserCompatible: false, hostedCompatible: true, liteCompatible: true),
            CreateTool("domain-overview", ToolCategory.Overview, browserCompatible: false, hostedCompatible: true, liteCompatible: true),
            CreateTool("spf", ToolCategory.EmailSecurity),
            CreateTool("dkim", ToolCategory.EmailSecurity),
            CreateTool("dmarc", ToolCategory.EmailSecurity),
            CreateTool("dnssec", ToolCategory.Dns),
            CreateTool("ct-subdomains", ToolCategory.Subdomain, browserCompatible: false, hostedCompatible: true)
        };
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
