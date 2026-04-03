using DomainDetective.Toolbox.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DomainDetective.Website.Tests;

public sealed class ToolsPageComponentTests : TestContext {
    public ToolsPageComponentTests() {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "StaticOnly"
            })
            .Build();

        Services.AddSingleton<IConfiguration>(configuration);
        Services.AddSingleton<ToolRegistry>();
        Services.AddScoped<ToolAvailabilityService>();
    }

    [Fact]
    public void ToolsPageShowsGuidedWorkflowContentAndPreservesSelectedDomain() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?q=contoso.com");

        var cut = RenderComponent<DomainDetective.Website.Pages.Tools>();

        var plannerDomain = cut.Find("#tool-plan-domain");
        Assert.Equal("contoso.com", plannerDomain.GetAttribute("value"));

        Assert.Contains("Guided Local Workflows", cut.Markup);
        Assert.Contains("Guided workflows: 5", cut.Markup);
        Assert.Contains("/tools/ct-subdomains/?q=contoso.com", cut.Markup);
        Assert.Contains("Start with an overview", cut.Markup);
        Assert.Contains("DnsClientX-powered DNS workspace", cut.Markup);
        Assert.Contains("/tools/dns-lookup/?q=contoso.com", cut.Markup);
        Assert.Contains("/docs/dnsclientx/", cut.Markup);
        Assert.Contains("/docs/dns-workspace/", cut.Markup);
        Assert.Contains("/docs/dns-examples/", cut.Markup);
        Assert.Contains("/docs/dns-resolvers/", cut.Markup);
        Assert.Contains("Guided locally", cut.Markup);
    }
}
