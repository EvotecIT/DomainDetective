using DnsClientX;
using System.Net.Http;

namespace DomainDetective.Toolbox.Services;

/// <summary>
/// Adapts browser HttpClient for use with DomainDetective's DomainHealthCheck.
/// Configures DoH (DNS-over-HTTPS) for browser compatibility.
/// </summary>
public sealed class BrowserDnsService {
    private readonly HttpClient _httpClient;

    public BrowserDnsService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public DomainHealthCheck CreateHealthCheck() {
        var healthCheck = new DomainHealthCheck();
        healthCheck.DnsEndpoint = DnsEndpoint.CloudflareWireFormat;
        healthCheck.HttpClientFactory = new BrowserHttpClientFactory(_httpClient);
        return healthCheck;
    }

    private sealed class BrowserHttpClientFactory : DomainDetective.IHttpClientFactory {
        private readonly HttpClient _client;

        public BrowserHttpClientFactory(HttpClient client) {
            _client = client;
        }

        public HttpClient CreateClient() => _client;
    }
}
