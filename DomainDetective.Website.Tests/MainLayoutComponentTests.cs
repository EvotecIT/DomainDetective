using Microsoft.JSInterop;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using System.Net.Http;

namespace DomainDetective.Website.Tests;

public sealed class MainLayoutComponentTests : TestContext {
    public MainLayoutComponentTests() {
        JSInterop.SetupVoid("domainDetectiveTools.initTheme");
        JSInterop.SetupVoid("domainDetectiveTools.toggleTheme");
        Services.AddScoped(_ => new HttpClient(new StaticHttpMessageHandler()) {
            BaseAddress = new Uri("http://localhost")
        });
        Services.AddScoped<DomainDetective.Website.Services.SiteNavigationService>();
    }

    [Fact]
    public void LayoutUsesFallbackNavigationWhenSharedSiteNavigationIsUnavailable() {
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        var toolsLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "Tools");
        var tryOnlineLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Contains("Try Online", StringComparison.Ordinal));
        var allToolsLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "All Tools");
        var dnsDocsLink = cut.FindAll("a").Single(anchor => anchor.TextContent.Trim() == "DnsClientX Docs");

        Assert.Equal("/tools/", toolsLink.GetAttribute("href"));
        Assert.Equal("/tools/", tryOnlineLink.GetAttribute("href"));
        Assert.Equal("/tools/", allToolsLink.GetAttribute("href"));
        Assert.Equal("/docs/dnsclientx/", dnsDocsLink.GetAttribute("href"));
    }

    [Fact]
    public void LayoutOpensMobileNavigationWhenToggleIsClicked() {
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        cut.Find("button.dd-nav-toggle").Click();

        var nav = cut.Find("nav.dd-nav");
        Assert.Contains("open", nav.ClassList);
    }

    [Fact]
    public void LayoutMarksApiNavigationAsActiveInsideApiSection() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/api/powershell/");
        RenderFragment body = builder => builder.AddMarkupContent(0, "<p>Body</p>");

        var cut = RenderComponent<DomainDetective.Website.Layout.MainLayout>(parameters => parameters
            .Add(component => component.Body, body));

        var apiTrigger = cut.Find("button.dd-nav-dropdown-trigger");
        Assert.Contains("is-active", apiTrigger.ClassList);
    }

    private sealed class StaticHttpMessageHandler : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}
