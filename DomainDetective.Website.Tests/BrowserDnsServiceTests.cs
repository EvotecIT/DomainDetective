using System.Net;
using System.Net.Http;
using DomainDetective.Toolbox.Services;

namespace DomainDetective.Website.Tests;

public sealed class BrowserDnsServiceTests {
    [Fact]
    public async Task CreateHealthCheckUsesSelectedResolverForBrowserDnsQueries() {
        var handler = new RecordingMessageHandler();
        using var httpClient = new HttpClient(handler);
        var service = new BrowserDnsService(httpClient);

        var healthCheck = service.CreateHealthCheck("Cloudflare DNS");
        await healthCheck.VerifyDnsInventoryAsync("contoso.com");

        Assert.NotEmpty(handler.RequestUris);
        Assert.All(handler.RequestUris, uri => Assert.Equal("cloudflare-dns.com", uri.Host));
    }

    [Fact]
    public void GetResolverProfileFallsBackToDefaultResolverForUnknownName() {
        var resolver = BrowserDnsService.GetResolverProfile("Unknown Resolver");

        Assert.Equal(BrowserDnsService.GetDefaultResolverName(), resolver.Name);
    }

    private sealed class RecordingMessageHandler : HttpMessageHandler {
        public List<Uri> RequestUris { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            RequestUris.Add(request.RequestUri!);

            var response = new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent("{\"Status\":0,\"AD\":false,\"Answer\":[],\"Authority\":[]}")
            };

            return Task.FromResult(response);
        }
    }
}
