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

    [Fact]
    public async Task BrowserDohMapsExtendedResponseCodesUsingWireWidth() {
        var handler = new RecordingMessageHandler(status: 16);
        using var httpClient = new HttpClient(handler);
        var service = new BrowserDnsService(httpClient);
        var healthCheck = service.CreateHealthCheck();

        var responses = await healthCheck.DnsConfiguration.QueryFullDNS(new[] { "contoso.com" }, DnsClientX.DnsRecordType.A);

        Assert.Equal(DnsClientX.DnsResponseCode.BadVersion, Assert.Single(responses).Status);
    }

    private sealed class RecordingMessageHandler : HttpMessageHandler {
        private readonly int _status;

        public RecordingMessageHandler(int status = 0) {
            _status = status;
        }

        public List<Uri> RequestUris { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            RequestUris.Add(request.RequestUri!);

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = new StringContent(
                    $"{{\"Status\":{_status},\"AD\":false,\"Answer\":[],\"Authority\":[]}}",
                    System.Text.Encoding.UTF8,
                    "application/dns-json")
            });
        }
    }
}
