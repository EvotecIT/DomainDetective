using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

internal sealed partial class NativeCtLogSubdomainDiscovery {
    private async Task<IReadOnlyList<RawCtEntryPayload>> GetEntriesAsync(string logUrl, long start, long end,
        NativeCtLogSubdomainDiscoveryOptions options, CancellationToken cancellationToken) {
        if (start > end) return Array.Empty<RawCtEntryPayload>();
        string json = await FetchJsonWithRetryAsync(CombineLogUrl(logUrl, $"ct/v1/get-entries?start={start}&end={end}"),
            options, cancellationToken).ConfigureAwait(false);
        await DelayIfRequestedAsync(options.RequestDelay, cancellationToken).ConfigureAwait(false);
        // Keep every returned log position, including undecodable entries. Dropping an item
        // changes the index of every following certificate and makes cursor progress unsafe.
        return CtLogIngestionClient.ParseEntryPayloads(json, start, end, cancellationToken);
    }

    private async Task<string> FetchJsonAsync(string url, TimeSpan requestTimeout, CancellationToken cancellationToken) {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (requestTimeout > TimeSpan.Zero && requestTimeout != Timeout.InfiniteTimeSpan) deadline.CancelAfter(requestTimeout);
        var client = new CtLogIngestionClient { HttpGetOverride = QueryOverride };
        try {
            return await client.FetchJsonAsync(url, Timeout.InfiniteTimeSpan, deadline.Token).ConfigureAwait(false);
        } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested) {
            throw new TimeoutException($"Native CT request timed out after {requestTimeout} for {url}.");
        }
    }
}
