using DomainDetective.Toolbox.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http;

namespace DomainDetective.Website.Tests;

public sealed class ToolsPageComponentTests : BunitContext {
    public ToolsPageComponentTests() {
        JSInterop.Mode = JSRuntimeMode.Loose;

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "StaticOnly"
            })
            .Build();

        Services.AddSingleton<IConfiguration>(configuration);
        Services.AddSingleton<ToolRegistry>();
        Services.AddScoped(_ => new HttpClient(new StaticHttpMessageHandler()) {
            BaseAddress = new Uri("http://localhost")
        });
        Services.AddScoped<ToolAvailabilityService>();
    }

    [Fact]
    public void ToolsPageShowsSimpleCatalogAndLegendInStaticMode() {
        var cut = Render<DomainDetective.Website.Pages.Tools>();

        cut.WaitForAssertion(() => {
            Assert.Contains("Domain Analysis Tools", cut.Markup);
            Assert.Contains("Web-ready domain security analysis with live DNS, mail, adaptive overview checks, and local workflows for deeper tools.", cut.Markup);
            Assert.Contains("Runs in browser", cut.Markup);
            Assert.Contains("Partial browser support", cut.Markup);
            Assert.Contains("Run locally (CLI / PowerShell)", cut.Markup);
            Assert.Contains("/tools/dns-lookup/", cut.Markup);
            Assert.Contains("/tools/raw-dns-query/", cut.Markup);
            Assert.Contains("/tools/domain-overview/", cut.Markup);
            Assert.DoesNotContain("Guided Local Workflows", cut.Markup);
        });
    }

    [Fact]
    public void ToolsPageRedirectsLegacyDomainQueryToDomainOverview() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?domain=contoso.com");

        Render<DomainDetective.Website.Pages.Tools>();

        Assert.Equal("http://localhost/tools/domain-overview/?q=contoso.com", navigation.Uri);
    }

    [Fact]
    public void ToolsPagePreservesQDomainInCatalogLinks() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/?q=evotec.pl");

        var cut = Render<DomainDetective.Website.Pages.Tools>();

        cut.WaitForAssertion(() => {
            Assert.Contains("/tools/spf/?q=evotec.pl", cut.Markup);
            Assert.Contains("/tools/cert-check/?q=evotec.pl", cut.Markup);
        });
    }

    [Fact]
    public void HostedOnlyToolUsesDomainQueryInLocalCommand() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/cert-check/?q=evotec.pl");

        var cut = Render<DomainDetective.Website.Pages.Tools>(parameters => parameters
            .Add(component => component.ToolSlug, "cert-check"));

        cut.WaitForAssertion(() => {
            Assert.Contains("Run deeper locally", cut.Markup);
            Assert.Contains("Test-DDDomainCertificate -Url", cut.Markup);
            Assert.Contains("evotec.pl", cut.Markup);
            Assert.DoesNotContain("_domain", cut.Markup);
        });
    }

    private sealed class StaticHttpMessageHandler : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            return Task.FromResult(CreateNotFoundResponse());
        }

        private static HttpResponseMessage CreateNotFoundResponse() {
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }
}
