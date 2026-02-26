using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
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

    private static readonly ConcurrentDictionary<string, CacheItem> SharedResponseCache = new(StringComparer.Ordinal);
    private static readonly SemaphoreSlim SharedRequestGate = new(1, 1);
    private static readonly object SharedCacheMaintenanceLock = new();
    private static DateTimeOffset _lastRequestUtc = DateTimeOffset.MinValue;

    /// <summary>CT log API templates containing a {0} placeholder for the fingerprint.</summary>
    public List<string> ApiTemplates { get; } = new() { "https://crt.sh/?sha256={0}&output=json" };
    /// <summary>How long successful CT responses should be cached.</summary>
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromMinutes(30);
    /// <summary>Maximum number of shared cached CT responses kept in memory.</summary>
    public int MaxCacheEntries { get; set; } = 20000;
    /// <summary>Minimum spacing between outbound CT requests across all aggregator instances.</summary>
    public TimeSpan MinimumRequestSpacing { get; set; } = TimeSpan.FromMilliseconds(250);
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
        if (string.IsNullOrWhiteSpace(fingerprint))
        {
            return results;
        }

        if (QueryOverride != null)
        {
            var json = await QueryOverride(fingerprint).ConfigureAwait(false);
            AppendEntries(ParseEntries(json), results);
            return results;
        }

        var client = CreateClient(out var dispose);
        try
        {
            foreach (var template in ApiTemplates)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var url = string.Format(template, fingerprint);
                if (TryGetCachedEntries(url, out var cachedEntries))
                {
                    AppendEntries(cachedEntries, results);
                    continue;
                }

                var fetchedEntries = await FetchEntriesWithRetryAsync(client, url, cancellationToken).ConfigureAwait(false);
                if (fetchedEntries.Count == 0)
                {
                    continue;
                }

                CacheEntries(url, fetchedEntries);
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

    private async Task<IReadOnlyList<JsonElement>> FetchEntriesWithRetryAsync(HttpClient client, string url, CancellationToken cancellationToken)
    {
        var attempts = Math.Max(1, MaxAttemptsPerRequest);
        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                await WaitForRateLimitAsync(cancellationToken).ConfigureAwait(false);
                using var response = await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
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
            catch (Exception ex) when (IsTransientException(ex) && attempt < attempts)
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

    private async Task WaitForRateLimitAsync(CancellationToken cancellationToken)
    {
        var minimumSpacing = MinimumRequestSpacing;
        if (minimumSpacing <= TimeSpan.Zero)
        {
            return;
        }

        await SharedRequestGate.WaitAsync(cancellationToken).ConfigureAwait(false);
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
            SharedRequestGate.Release();
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

    private static bool IsTransientException(Exception exception)
    {
        return exception is HttpRequestException ||
               exception is TaskCanceledException ||
               exception is TimeoutException;
    }

    private static bool ShouldRetryStatusCode(HttpStatusCode statusCode)
    {
        var value = (int)statusCode;
        return statusCode == HttpStatusCode.RequestTimeout ||
               statusCode == HttpStatusCode.BadGateway ||
               statusCode == HttpStatusCode.ServiceUnavailable ||
               statusCode == HttpStatusCode.GatewayTimeout ||
               statusCode == HttpStatusCode.InternalServerError ||
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
        var ticks = RetryDelay.Ticks * multiplier;
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
            results.Add(entry.Clone());
        }
    }

    private bool TryGetCachedEntries(string url, out IReadOnlyList<JsonElement> entries)
    {
        entries = Array.Empty<JsonElement>();
        var ttl = CacheTtl;
        if (ttl <= TimeSpan.Zero)
        {
            return false;
        }

        if (!SharedResponseCache.TryGetValue(url, out var cached))
        {
            return false;
        }

        if (cached.ExpiresUtc < DateTimeOffset.UtcNow)
        {
            SharedResponseCache.TryRemove(url, out _);
            return false;
        }

        entries = cached.Entries;
        return true;
    }

    private void CacheEntries(string url, IReadOnlyList<JsonElement> entries)
    {
        var ttl = CacheTtl;
        if (ttl <= TimeSpan.Zero || entries.Count == 0)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        SharedResponseCache[url] = new CacheItem
        {
            CreatedUtc = now,
            ExpiresUtc = now + ttl,
            Entries = entries.Select(entry => entry.Clone()).ToList()
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

    internal static void ResetSharedStateForTests()
    {
        SharedResponseCache.Clear();
        _lastRequestUtc = DateTimeOffset.MinValue;
    }
}
