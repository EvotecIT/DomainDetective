using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Retrieves certificate transparency log entries from multiple APIs.
/// </summary>
public sealed class CtLogAggregator
{
    private sealed class CacheItem
    {
        public DateTimeOffset CreatedUtc { get; init; }
        public DateTimeOffset ExpiresUtc { get; init; }
        public List<JsonElement> Entries { get; init; } = new();
    }

    private sealed class CtDiscoveryRequest
    {
        public string SourceName { get; init; } = string.Empty;
        public string Url { get; init; } = string.Empty;
        public string CacheKey { get; init; } = string.Empty;
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static readonly ConcurrentDictionary<string, CacheItem> SharedResponseCache = new(StringComparer.Ordinal);
    private static readonly object SharedRequestGateLock = new();
    private static SemaphoreSlim SharedRequestGate = new(1, 1);
    private static readonly object SharedCacheMaintenanceLock = new();
    private static readonly object SharedConfigurationLock = new();
    private static DateTimeOffset _lastRequestUtc = DateTimeOffset.MinValue;
    private static TimeSpan _sharedCacheTtl = TimeSpan.FromMinutes(30);
    private static int _sharedMaxCacheEntries = 20000;
    private static TimeSpan _sharedMinimumRequestSpacing = TimeSpan.FromMilliseconds(250);

    /// <summary>CT log API templates containing a {0} placeholder for the fingerprint.</summary>
    public List<string> ApiTemplates { get; } = new() { "https://crt.sh/?sha256={0}&output=json" };
    /// <summary>Enable Censys certificate discovery using the configured API credentials.</summary>
    public bool EnableCensysSource { get; set; }
    /// <summary>Censys API identifier (used with <see cref="CensysApiSecret"/>).</summary>
    public string? CensysApiId { get; set; }
    /// <summary>Censys API secret (used with <see cref="CensysApiId"/>).</summary>
    public string? CensysApiSecret { get; set; }
    /// <summary>Censys certificate API URL template. Use {0} for SHA-256 fingerprint.</summary>
    public string CensysApiUrlTemplate { get; set; } = "https://search.censys.io/api/v2/certificates/{0}";
    /// <summary>Enable Shodan certificate discovery using the configured API key.</summary>
    public bool EnableShodanSource { get; set; }
    /// <summary>Shodan API key used by <see cref="ShodanApiUrlTemplate"/>.</summary>
    public string? ShodanApiKey { get; set; }
    /// <summary>Shodan API URL template. Use {0} for SHA-256 fingerprint and {1} for URL-encoded API key.</summary>
    public string ShodanApiUrlTemplate { get; set; } = "https://api.shodan.io/shodan/host/search?key={1}&query=ssl.cert.fingerprint.sha256:{0}";
    /// <summary>Names of discovery sources queried in the last <see cref="QueryAsync"/> call.</summary>
    public IReadOnlyList<string> LastQueriedSources => _lastQueriedSources;

    private readonly List<string> _lastQueriedSources = new();
    /// <summary>How long successful CT responses should be cached (shared across all instances).</summary>
    public TimeSpan CacheTtl {
        get {
            lock (SharedConfigurationLock) {
                return _sharedCacheTtl;
            }
        }
        set {
            lock (SharedConfigurationLock) {
                _sharedCacheTtl = value;
            }
        }
    }

    /// <summary>Maximum number of shared cached CT responses kept in memory (shared across all instances).</summary>
    public int MaxCacheEntries {
        get {
            lock (SharedConfigurationLock) {
                return _sharedMaxCacheEntries;
            }
        }
        set {
            lock (SharedConfigurationLock) {
                _sharedMaxCacheEntries = value;
            }
        }
    }

    /// <summary>Minimum spacing between outbound CT requests across all aggregator instances.</summary>
    public TimeSpan MinimumRequestSpacing {
        get {
            lock (SharedConfigurationLock) {
                return _sharedMinimumRequestSpacing;
            }
        }
        set {
            lock (SharedConfigurationLock) {
                _sharedMinimumRequestSpacing = value;
            }
        }
    }

    /// <summary>Maximum retry attempts per request when transient failures occur.</summary>
    public int MaxAttemptsPerRequest { get; set; } = 3;
    /// <summary>Base delay applied between retries.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromMilliseconds(750);

    /// <summary>Optional HTTP handler factory for testing.</summary>
    internal Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

    /// <summary>Optional override returning the JSON content for a fingerprint.</summary>
    public Func<string, Task<string>>? QueryOverride { get; set; }

    /// <summary>Optional delay override for tests.</summary>
    internal Func<TimeSpan, CancellationToken, Task>? DelayOverride { get; set; }

    /// <summary>
    /// Queries all configured APIs for the specified SHA-256 fingerprint.
    /// </summary>
    /// <param name="fingerprint">SHA-256 certificate fingerprint.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>List of JSON elements describing log entries.</returns>
    public async Task<IReadOnlyList<JsonElement>> QueryAsync(string fingerprint, CancellationToken cancellationToken = default)
    {
        var results = new List<JsonElement>();
        _lastQueriedSources.Clear();
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return results;
        }

        if (QueryOverride != null)
        {
            _lastQueriedSources.Add("override");
            var json = await QueryOverride(fingerprint).ConfigureAwait(false);
            AppendEntries(ParseEntries(json), results);
            return results;
        }

        var requests = BuildDiscoveryRequests(fingerprint);
        if (requests.Count == 0)
        {
            return results;
        }

        var client = CreateClient(out var dispose);
        try
        {
            foreach (var request in requests)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (TryGetCachedEntries(request.CacheKey, out var cachedEntries))
                {
                    AppendEntries(cachedEntries, results);
                    continue;
                }

                var fetchedEntries = await FetchEntriesWithRetryAsync(client, request, cancellationToken).ConfigureAwait(false);
                if (fetchedEntries.Count == 0)
                {
                    continue;
                }

                CacheEntries(request.CacheKey, fetchedEntries);
                AppendEntries(fetchedEntries, results);
            }
        }
        finally
        {
            if (dispose)
            {
                client.Dispose();
            }
        }

        return results;
    }

    private List<CtDiscoveryRequest> BuildDiscoveryRequests(string fingerprint)
    {
        var requests = new List<CtDiscoveryRequest>();
        var seenSources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var template in ApiTemplates)
        {
            var url = SafeFormat(template, fingerprint);
            if (string.IsNullOrWhiteSpace(url))
            {
                continue;
            }

            var sourceName = InferSourceName(url, "crt.sh");
            requests.Add(new CtDiscoveryRequest
            {
                SourceName = sourceName,
                Url = url,
                CacheKey = $"template:{url}"
            });
            if (seenSources.Add(sourceName))
            {
                _lastQueriedSources.Add(sourceName);
            }
        }

        if (EnableCensysSource && !string.IsNullOrWhiteSpace(CensysApiId) && !string.IsNullOrWhiteSpace(CensysApiSecret))
        {
            var url = SafeFormat(CensysApiUrlTemplate, fingerprint);
            if (!string.IsNullOrWhiteSpace(url))
            {
                var authorization = BuildBasicAuthorizationHeader(CensysApiId!, CensysApiSecret!);
                requests.Add(new CtDiscoveryRequest
                {
                    SourceName = "censys",
                    Url = url,
                    CacheKey = $"censys:{url}:{CensysApiId}",
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Authorization"] = authorization
                    }
                });
                if (seenSources.Add("censys"))
                {
                    _lastQueriedSources.Add("censys");
                }
            }
        }

        if (EnableShodanSource && !string.IsNullOrWhiteSpace(ShodanApiKey))
        {
            var escapedApiKey = Uri.EscapeDataString(ShodanApiKey);
            var url = SafeFormat(ShodanApiUrlTemplate, fingerprint, escapedApiKey);
            if (!string.IsNullOrWhiteSpace(url))
            {
                requests.Add(new CtDiscoveryRequest
                {
                    SourceName = "shodan",
                    Url = url,
                    CacheKey = $"shodan:{url}"
                });
                if (seenSources.Add("shodan"))
                {
                    _lastQueriedSources.Add("shodan");
                }
            }
        }

        return requests;
    }

    private async Task<IReadOnlyList<JsonElement>> FetchEntriesWithRetryAsync(HttpClient client, CtDiscoveryRequest request, CancellationToken cancellationToken)
    {
        var attempts = Math.Max(1, MaxAttemptsPerRequest);
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await WaitForRateLimitAsync(cancellationToken).ConfigureAwait(false);
                using var message = new HttpRequestMessage(HttpMethod.Get, request.Url);
                foreach (var header in request.Headers)
                {
                    message.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }

                using var response = await client.SendAsync(message, cancellationToken).ConfigureAwait(false);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    return ParseEntries(json);
                }

                if (!ShouldRetryStatusCode(response.StatusCode) || attempt == attempts)
                {
                    return Array.Empty<JsonElement>();
                }
            }
            catch (Exception ex) when (IsTransientException(ex, cancellationToken) && attempt < attempts)
            {
                // Continue with retry path.
            }

            var delay = ComputeBackoff(attempt);
            if (delay > TimeSpan.Zero)
            {
                await DelayAsync(delay, cancellationToken).ConfigureAwait(false);
            }
        }

        return Array.Empty<JsonElement>();
    }

    private static string BuildBasicAuthorizationHeader(string apiId, string apiSecret)
    {
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{apiId}:{apiSecret}"));
        return $"Basic {encoded}";
    }

    private static string SafeFormat(string template, params object[] args)
    {
        if (string.IsNullOrWhiteSpace(template))
        {
            return string.Empty;
        }

        try
        {
            return string.Format(template, args);
        }
        catch (FormatException)
        {
            return string.Empty;
        }
    }

    private static string InferSourceName(string url, string fallback)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host;
        }

        return fallback;
    }

    private async Task WaitForRateLimitAsync(CancellationToken cancellationToken)
    {
        var minimumSpacing = MinimumRequestSpacing;
        if (minimumSpacing <= TimeSpan.Zero)
        {
            return;
        }

        SemaphoreSlim requestGate;
        lock (SharedRequestGateLock)
        {
            requestGate = SharedRequestGate;
        }

        await requestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var now = DateTimeOffset.UtcNow;
            var nextAllowed = _lastRequestUtc + minimumSpacing;
            if (nextAllowed > now)
            {
                await DelayAsync(nextAllowed - now, cancellationToken).ConfigureAwait(false);
            }

            _lastRequestUtc = DateTimeOffset.UtcNow;
        }
        finally
        {
            requestGate.Release();
        }
    }

    private async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        if (delay <= TimeSpan.Zero)
        {
            return;
        }

        if (DelayOverride != null)
        {
            await DelayOverride(delay, cancellationToken).ConfigureAwait(false);
            return;
        }

        await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
    }

    private static bool IsTransientException(Exception exception, CancellationToken cancellationToken)
    {
        if (exception is TaskCanceledException)
        {
            return !cancellationToken.IsCancellationRequested;
        }

        return exception is HttpRequestException ||
               exception is TimeoutException;
    }

    private static bool ShouldRetryStatusCode(HttpStatusCode statusCode)
    {
        var value = (int)statusCode;
        return statusCode == HttpStatusCode.RequestTimeout ||
               statusCode == HttpStatusCode.BadGateway ||
               statusCode == HttpStatusCode.ServiceUnavailable ||
               statusCode == HttpStatusCode.GatewayTimeout ||
               value == 429 ||
               value == 425;
    }

    private TimeSpan ComputeBackoff(int attempt)
    {
        if (RetryDelay <= TimeSpan.Zero)
        {
            return TimeSpan.Zero;
        }

        var multiplier = Math.Max(1, attempt);
        long ticks;
        try
        {
            ticks = checked(RetryDelay.Ticks * (long)multiplier);
        }
        catch (OverflowException)
        {
            return TimeSpan.MaxValue;
        }

        if (ticks <= 0 || ticks >= TimeSpan.MaxValue.Ticks)
        {
            return TimeSpan.MaxValue;
        }

        return TimeSpan.FromTicks(ticks);
    }

    private static IReadOnlyList<JsonElement> ParseEntries(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return Array.Empty<JsonElement>();
        }

        try
        {
            var parsed = new List<JsonElement>();
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in doc.RootElement.EnumerateArray())
                {
                    parsed.Add(entry.Clone());
                }
            }
            else if (doc.RootElement.ValueKind != JsonValueKind.Undefined && doc.RootElement.ValueKind != JsonValueKind.Null)
            {
                parsed.Add(doc.RootElement.Clone());
            }

            return parsed;
        }
        catch
        {
            // ignore parse errors
            return Array.Empty<JsonElement>();
        }
    }

    private static void AppendEntries(IEnumerable<JsonElement> entries, ICollection<JsonElement> results)
    {
        foreach (var entry in entries)
        {
            results.Add(entry);
        }
    }

    private bool TryGetCachedEntries(string cacheKey, out IReadOnlyList<JsonElement> entries)
    {
        entries = Array.Empty<JsonElement>();
        var ttl = CacheTtl;
        if (ttl <= TimeSpan.Zero)
        {
            return false;
        }

        if (!SharedResponseCache.TryGetValue(cacheKey, out var cached))
        {
            return false;
        }

        if (cached.ExpiresUtc < DateTimeOffset.UtcNow)
        {
            SharedResponseCache.TryRemove(cacheKey, out _);
            return false;
        }

        entries = cached.Entries;
        return true;
    }

    private void CacheEntries(string cacheKey, IReadOnlyList<JsonElement> entries)
    {
        var ttl = CacheTtl;
        if (ttl <= TimeSpan.Zero || entries.Count == 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        SharedResponseCache[cacheKey] = new CacheItem
        {
            CreatedUtc = now,
            ExpiresUtc = now + ttl,
            Entries = entries.ToList()
        };

        TrimCacheIfNeeded();
    }

    private void TrimCacheIfNeeded()
    {
        var maxEntries = MaxCacheEntries;
        if (maxEntries <= 0 || SharedResponseCache.Count <= maxEntries)
        {
            return;
        }

        lock (SharedCacheMaintenanceLock)
        {
            if (SharedResponseCache.Count <= maxEntries)
            {
                return;
            }

            var now = DateTimeOffset.UtcNow;
            foreach (var expired in SharedResponseCache.Where(pair => pair.Value.ExpiresUtc < now).ToList())
            {
                SharedResponseCache.TryRemove(expired.Key, out _);
            }

            if (SharedResponseCache.Count <= maxEntries)
            {
                return;
            }

            var overflow = SharedResponseCache.Count - maxEntries;
            foreach (var pair in SharedResponseCache.OrderBy(pair => pair.Value.CreatedUtc).Take(overflow).ToList())
            {
                SharedResponseCache.TryRemove(pair.Key, out _);
            }
        }
    }

    private HttpClient CreateClient(out bool dispose)
    {
        if (HttpHandlerFactory != null)
        {
            dispose = true;
            return new HttpClient(HttpHandlerFactory(), disposeHandler: true);
        }

        dispose = false;
        return SharedHttpClient.Instance;
    }

    [EditorBrowsable(EditorBrowsableState.Never)]
    internal static void ResetSharedStateForTests()
    {
        SharedResponseCache.Clear();
        _lastRequestUtc = DateTimeOffset.MinValue;
        lock (SharedConfigurationLock)
        {
            _sharedCacheTtl = TimeSpan.FromMinutes(30);
            _sharedMaxCacheEntries = 20000;
            _sharedMinimumRequestSpacing = TimeSpan.FromMilliseconds(250);
        }

        lock (SharedRequestGateLock)
        {
            SharedRequestGate = new SemaphoreSlim(1, 1);
        }
    }
}
