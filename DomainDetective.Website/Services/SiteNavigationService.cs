using System.Net.Http.Json;
using DomainDetective.Website.Models;

namespace DomainDetective.Website.Services;

public sealed class SiteNavigationService {
    private readonly HttpClient _httpClient;
    private SiteNavigationData? _cachedNavigation;

    public SiteNavigationService(HttpClient httpClient) {
        _httpClient = httpClient;
    }

    public async Task<SiteNavigationData?> GetNavigationAsync(CancellationToken cancellationToken = default) {
        if (_cachedNavigation != null) {
            return _cachedNavigation;
        }

        try {
            _cachedNavigation = await _httpClient.GetFromJsonAsync<SiteNavigationData>("/data/site-nav.json", cancellationToken);
        } catch {
            _cachedNavigation = null;
        }

        return _cachedNavigation;
    }
}
