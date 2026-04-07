using System.Net.Http.Json;
using System.Text.Json;
using DomainDetective.Website.Models;

namespace DomainDetective.Website.Services;

public sealed class SiteNavigationService {
    private readonly HttpClient _httpClient;
    private bool _attemptedFetch;
    private SiteNavigationData? _cachedNavigation;

    public SiteNavigationService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public async Task<SiteNavigationData?> GetNavigationAsync(CancellationToken cancellationToken = default) {
        if (_cachedNavigation != null || _attemptedFetch) {
            return _cachedNavigation;
        }

        try {
            _attemptedFetch = true;
            _cachedNavigation = await _httpClient.GetFromJsonAsync<SiteNavigationData>("/data/site-nav.json", cancellationToken);
        } catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException or JsonException or NotSupportedException) {
            _cachedNavigation = null;
        }

        return _cachedNavigation;
    }
}
