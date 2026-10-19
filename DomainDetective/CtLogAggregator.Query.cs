using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CtLogAggregator {
    private readonly object _queryStateLock = new();
    private long _latestQuery;
    private volatile CtLogQueryResult _lastQueryResult = CtLogQueryResult.Empty;

    /// <summary>Queries configured APIs and returns their entries. Concurrent callers needing completion evidence should use <see cref="QueryWithResultAsync(string, CancellationToken)"/>.</summary>
    /// <param name="fingerprint">SHA-256 certificate fingerprint.</param>
    /// <param name="cancellationToken">Token used to cancel the query.</param>
    /// <returns>Entries belonging to this query.</returns>
    public async Task<IReadOnlyList<JsonElement>> QueryAsync(string fingerprint, CancellationToken cancellationToken = default) =>
        (await QueryWithResultAsync(fingerprint, cancellationToken).ConfigureAwait(false)).Entries;

    /// <summary>Queries configured APIs and returns entries together with their query-specific completion and source evidence.</summary>
    /// <param name="fingerprint">SHA-256 certificate fingerprint.</param>
    /// <param name="cancellationToken">Token used to cancel the query.</param>
    /// <returns>A snapshot belonging to this query, independent of concurrent queries on this aggregator.</returns>
    public Task<CtLogQueryResult> QueryWithResultAsync(string fingerprint, CancellationToken cancellationToken = default) =>
        QueryWithResultAsync(fingerprint, cancellationToken, null);

    // Certificate lookup deadlines need the same query's partial evidence even when cancellation throws.
    internal async Task<CtLogQueryResult> QueryWithResultAsync(string fingerprint, CancellationToken cancellationToken,
        Action<CtLogQueryResult>? completedSnapshot) {
        long query;
        lock (_queryStateLock) {
            query = ++_latestQuery;
            _lastQueryResult = CtLogQueryResult.Empty;
        }
        var entries = new List<JsonElement>();
        var sources = new List<string>();
        var errors = new List<string>();
        bool complete = false;
        try {
            cancellationToken.ThrowIfCancellationRequested();
            if (!string.IsNullOrWhiteSpace(fingerprint)) {
                var queryOverride = QueryOverride;
                if (queryOverride != null) {
                    sources.Add("override");
                    var json = await queryOverride(fingerprint).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
                    var parsed = ParseFetchResult(json, CtResponseParserKind.Standard);
                    AppendEntries(parsed.Entries, entries);
                    complete = parsed.Complete;
                } else {
                    var requests = BuildDiscoveryRequests(fingerprint, sources, errors);
                    bool valid = requests.Count > 0 && errors.Count == 0;
                    var fetched = new FetchResult?[requests.Count];
                    try {
                        await Helpers.BoundedAsync.RunAsync(System.Linq.Enumerable.Range(0, requests.Count).ToArray(), async index => {
                            var request = requests[index];
                            fetched[index] = TryGetCachedEntries(request.CacheKey, out var cached)
                                ? new FetchResult(true, cached)
                                : await FetchSharedAsync(request, cancellationToken).ConfigureAwait(false);
                            return true;
                        }, 4, cancellationToken).ConfigureAwait(false);
                    } finally {
                        // Merge after every admitted request drains, retaining partial evidence
                        // on cancellation and stable configured-source order on success.
                        foreach (var result in fetched) {
                            valid &= result?.Complete == true;
                            if (result != null) { AppendEntries(result.Entries, entries); }
                        }
                    }
                    complete = valid;
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new CtLogQueryResult(entries, complete, sources, errors);
        } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
            complete = false;
            throw new OperationCanceledException(cancellationToken);
        } catch {
            complete = false;
            throw;
        } finally {
            var snapshot = new CtLogQueryResult(entries, complete, sources, errors);
            lock (_queryStateLock) {
                if (query == _latestQuery) { _lastQueryResult = snapshot; }
            }
            completedSnapshot?.Invoke(snapshot);
        }
    }
}
