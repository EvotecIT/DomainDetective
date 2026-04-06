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
    public void ToolsPageShowsSimpleCatalogLegend() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?q=contoso.com");

        var cut = RenderComponent<DomainDetective.Website.Pages.Tools>();

        Assert.Contains("Runs in browser", cut.Markup);
        Assert.Contains("Partial browser support", cut.Markup);
        Assert.Contains("Run locally (CLI / PowerShell)", cut.Markup);
        Assert.DoesNotContain("Guided Local Workflows", cut.Markup);
        Assert.DoesNotContain("DnsClientX-powered DNS workspace", cut.Markup);
        Assert.DoesNotContain("Start with an overview", cut.Markup);
    }

    [Fact]
    public void ToolsPageRedirectsLegacyDomainQueryToDomainOverview() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?domain=contoso.com");

        RenderComponent<DomainDetective.Website.Pages.Tools>();

        Assert.Equal("http://localhost/tools/domain-overview/?q=contoso.com", navigation.Uri);
    }
}
