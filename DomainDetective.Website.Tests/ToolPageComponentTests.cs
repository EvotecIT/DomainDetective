using System.Net;
using System.Net.Http;
using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DomainDetective.Website.Tests;

public sealed class ToolPageComponentTests : TestContext {
    private static readonly TimeSpan AsyncToolRenderTimeout = TimeSpan.FromSeconds(10);

    private readonly ToolRegistry _registry = new();
    private readonly RecordingDnsHandler _dnsHandler = new();

    public ToolPageComponentTests() {
        JSInterop.Mode = JSRuntimeMode.Loose;

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "StaticOnly"
            })
            .Build();

        Services.AddSingleton<IConfiguration>(configuration);
        Services.AddSingleton(_registry);
        Services.AddScoped(_ => new HttpClient(_dnsHandler) {
            BaseAddress = new Uri("http://localhost")
        });
        Services.AddScoped<ToolAvailabilityService>();
        Services.AddScoped(_ => new BrowserDnsService(new HttpClient(_dnsHandler)));
        Services.AddScoped<BrowserOverviewService>();
        Services.AddScoped(_ => new HostedAnalysisService(new HttpClient(_dnsHandler) {
            BaseAddress = new Uri("http://localhost")
        }));
    }

    [Fact]
    public void DnsLookupPageShowsDnsWorkspaceAndRawQueryCallout() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/dns-lookup/?q=contoso.com&h=_dmarc&r=Cloudflare%20DNS&s=TXT");

        var tool = _registry.GetBySlug("dns-lookup")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        cut.WaitForAssertion(() => {
            var domainInput = cut.Find("form.tool-input-form input[type='text']");

            Assert.Equal("contoso.com", domainInput.GetAttribute("value"));
            Assert.Contains("Need raw record-by-record queries?", cut.Markup);
            Assert.Contains("Use <a href=\"/tools/raw-dns-query/\">Raw DNS Query</a>", cut.Markup);
            Assert.Contains("/tools/dns-query-playground/", cut.Markup);
            Assert.Contains("Analyze", cut.Markup);
            Assert.DoesNotContain("Tool not found", cut.Markup);
            Assert.Contains(_dnsHandler.RequestUris, uri => uri.Host.Equals("cloudflare-dns.com", StringComparison.OrdinalIgnoreCase));
        }, AsyncToolRenderTimeout);
    }

    [Fact]
    public void DnsLookupPageNormalizesUnknownResolverQueryToDefaultResolver() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/dns-lookup/?q=contoso.com&h=_dmarc&r=Cloudflaer&s=TXT");

        var tool = _registry.GetBySlug("dns-lookup")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        cut.WaitForAssertion(() => {
            Assert.Contains(_dnsHandler.RequestUris, uri => uri.Host.Equals("dns.google", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain("Cloudflaer", cut.Markup);
            Assert.Contains("/tools/dns-lookup/?q=contoso.com", navigation.Uri, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("r=Google%20DNS", navigation.Uri, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Cloudflaer", navigation.Uri, StringComparison.OrdinalIgnoreCase);
        }, AsyncToolRenderTimeout);
    }

    [Fact]
    public void M365OverviewBrowserLimitedTenantUsesNotConfirmedLanguage() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/m365-overview/?q=contoso.com");

        var tool = _registry.GetBySlug("m365-overview")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        cut.WaitForAssertion(() => {
            Assert.Contains("Not confirmed", cut.Markup);
            Assert.Contains("Tenant identity and Microsoft authentication probing need the deeper online run.", cut.Markup);
            Assert.Contains("Partial browser support", cut.Markup);
            Assert.Contains("Tenant identity and Microsoft authentication probes", cut.Markup);
            Assert.Contains("Run deeper locally", cut.Markup);
            Assert.Contains("Get-DomainHealthCheck -Domain", cut.Markup);
            Assert.Contains("contoso.com", cut.Markup);
            Assert.DoesNotContain("Not detected", cut.Markup);
        });
    }

    [Fact]
    public void RunnableToolPageShowsExampleDomainsAndRunsSelectedExample() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/m365-overview/");

        var tool = _registry.GetBySlug("m365-overview")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        var exampleButton = cut.FindAll("button.tool-example-chip")
            .Single(button => button.TextContent.Contains("evotec.pl", StringComparison.OrdinalIgnoreCase));

        exampleButton.Click();

        cut.WaitForAssertion(() => {
            Assert.Contains("q=evotec.pl", navigation.Uri);
            Assert.Contains("evotec.pl", cut.Find("form.tool-input-form input[type='text']").GetAttribute("value"));
        });
    }

    [Fact]
    public void HostedOnlyStaticToolExplainsGuidedLocalCoverage() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/cert-check/");

        var tool = _registry.GetBySlug("cert-check")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        Assert.Contains("Guided locally", cut.Markup);
        Assert.Contains("This check needs network access that the GitHub Pages browser edition cannot provide.", cut.Markup);
        Assert.Contains("Full DD analysis through CLI, PowerShell, or C#", cut.Markup);
    }

    private sealed class RecordingDnsHandler : HttpMessageHandler {
        public List<Uri> RequestUris { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            if (request.RequestUri != null) {
                RequestUris.Add(request.RequestUri);
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent("{\"Status\":0,\"AD\":false,\"Answer\":[],\"Authority\":[]}")
            });
        }
    }
}
