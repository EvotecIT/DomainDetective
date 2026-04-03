using System.Net;
using System.Net.Http;
using DomainDetective.Toolbox.Components.Shared;
using DomainDetective.Toolbox.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace DomainDetective.Website.Tests;

public sealed class ToolPageComponentTests : TestContext {
    private readonly ToolRegistry _registry = new();

    public ToolPageComponentTests() {
        JSInterop.Mode = JSRuntimeMode.Loose;

        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> {
                ["Tools:Mode"] = "StaticOnly"
            })
            .Build();

        Services.AddSingleton<IConfiguration>(configuration);
        Services.AddSingleton(_registry);
        Services.AddScoped<ToolAvailabilityService>();
        Services.AddScoped(_ => new BrowserDnsService(new HttpClient(new StaticDnsHandler())));
        Services.AddScoped<BrowserOverviewService>();
        Services.AddScoped(_ => new HostedAnalysisService(new HttpClient(new StaticDnsHandler()) {
            BaseAddress = new Uri("http://localhost")
        }));
    }

    [Fact]
    public void DnsLookupPageShowsResolverSelectorAndSelectedResolverState() {
        var navigation = Services.GetRequiredService<NavigationManager>();
        navigation.NavigateTo("http://localhost/tools/dns-lookup/?q=contoso.com&h=_dmarc&r=Cloudflare%20DNS&s=TXT");

        var tool = _registry.GetBySlug("dns-lookup")!;
        var cut = RenderComponent<ToolPage>(parameters => parameters
            .Add(component => component.Definition, tool));

        cut.WaitForAssertion(() => {
            var hostInput = cut.Find("input.tool-input-host");
            var select = cut.Find("select.tool-input-select");

            Assert.Equal("_dmarc", hostInput.GetAttribute("value"));
            Assert.Equal("Local host label", hostInput.GetAttribute("aria-label"));
            Assert.Contains("Cloudflare DNS", select.InnerHtml);
            Assert.Contains("Google DNS", select.InnerHtml);
            Assert.Contains("Cloudflare DNS", cut.Markup);
            Assert.Contains("DnsProvider Cloudflare", cut.Markup);
            Assert.DoesNotContain("Invalid domain name", cut.Markup);
            Assert.Contains("DnsClientX lane", cut.Markup);
            Assert.Contains("Preset views", cut.Markup);
            Assert.Contains("Quick host targets", cut.Markup);
            Assert.Contains("Local host target", cut.Markup);
            Assert.Contains("_dmarc.contoso.com", cut.Markup);
            Assert.Contains("Resolve-Dns -Name", cut.Markup);
            Assert.Contains("-Type TXT -DnsProvider Cloudflare", cut.Markup);
            Assert.Contains("var recordTypes = new[] { DnsRecordType.TXT };", cut.Markup);
            Assert.Contains("Focused export", cut.Markup);
            Assert.Contains("Advanced DNS workflows", cut.Markup);
            Assert.Contains("Copy JSON", cut.Markup);
            Assert.Contains("Copy zone text", cut.Markup);
            Assert.Contains("Copy host query", cut.Markup);
            Assert.Contains("Copy benchmark", cut.Markup);
            Assert.Contains("/docs/dns-examples/", cut.Markup);
            Assert.Contains("/docs/dns-resolvers/", cut.Markup);
            Assert.Contains("/docs/dnsclientx/", cut.Markup);
            Assert.Contains("/tools/dns-lookup/?q=contoso.com&amp;s=MX%2CTXT%2CCNAME&amp;r=Cloudflare%20DNS", cut.Markup);
            Assert.Contains("/tools/dns-lookup/?q=contoso.com&amp;s=TXT&amp;h=_dmarc&amp;r=Cloudflare%20DNS", cut.Markup);
            Assert.Contains("/tools/dns-lookup/?q=contoso.com&amp;s=TXT%2CCNAME&amp;h=default._domainkey&amp;r=Cloudflare%20DNS", cut.Markup);
        });
    }

    private sealed class StaticDnsHandler : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent("{\"Status\":0,\"AD\":false,\"Answer\":[],\"Authority\":[]}")
            });
        }
    }
}
