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
        Services.AddScoped(_ => new BrowserDnsService(new HttpClient(new StaticHttpMessageHandler())));
        Services.AddScoped<BrowserOverviewService>();
        Services.AddScoped(_ => new HostedAnalysisService(new HttpClient(new StaticHttpMessageHandler()) {
            BaseAddress = new Uri("http://localhost")
        }));
    }

    [Fact]
    public void ToolsRootRendersNothingBecauseTheHubIsStatic() {
        var cut = Render<DomainDetective.Website.Pages.Tools>();

        cut.WaitForAssertion(() => Assert.True(string.IsNullOrWhiteSpace(cut.Markup)));
    }

    [Fact]
    public void ToolRouteRendersOnlyTheInteractiveToolInsideTheStaticPage() {
        var cut = Render<DomainDetective.Website.Pages.Tools>(parameters => parameters
            .Add(component => component.ToolSlug, "spf"));

        cut.WaitForAssertion(() => {
            Assert.Contains("tool-input-form", cut.Markup);
            Assert.DoesNotContain("tool-page-header", cut.Markup);
            Assert.DoesNotContain("tool-breadcrumb", cut.Markup);
            Assert.DoesNotContain("tool-usage-examples", cut.Markup);
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
