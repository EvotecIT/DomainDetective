using System.Net.Http.Json;
using System.Text.Json;
using DomainDetective.Website.Models;

namespace DomainDetective.Website.Services;

public sealed class SiteNavigationService {
    private readonly HttpClient _httpClient;
    private readonly SemaphoreSlim _fetchLock = new(1, 1);
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
            await _fetchLock.WaitAsync(cancellationToken);
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            return _cachedNavigation;
        }

        try {
            if (_cachedNavigation != null || _attemptedFetch) {
                return _cachedNavigation;
            }

            try {
                _cachedNavigation = await _httpClient.GetFromJsonAsync<SiteNavigationData>("/data/site-nav.json", cancellationToken);
                _attemptedFetch = true;
            } catch (TaskCanceledException) {
                return _cachedNavigation;
            } catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or JsonException or NotSupportedException) {
                _attemptedFetch = true;
                _cachedNavigation = null;
            }
            return _cachedNavigation;
        } finally {
            _fetchLock.Release();
        }
    }
}
