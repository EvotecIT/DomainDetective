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
        Services.AddScoped(_ => new HttpClient(new StaticDnsHandler()) {
            BaseAddress = new Uri("http://localhost")
        });
        Services.AddScoped<ToolAvailabilityService>();
        Services.AddScoped(_ => new BrowserDnsService(new HttpClient(new StaticDnsHandler())));
        Services.AddScoped<BrowserOverviewService>();
        Services.AddScoped(_ => new HostedAnalysisService(new HttpClient(new StaticDnsHandler()) {
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
            Assert.Contains("Analyze", cut.Markup);
            Assert.DoesNotContain("Tool not found", cut.Markup);
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
