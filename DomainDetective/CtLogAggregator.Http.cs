using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public sealed partial class CtLogAggregator {
    // Read only successful evidence. Status-only retries must not wait for an
    // irrelevant error body; successful reads retain the client's existing limit
    // and content charset/BOM decoding while observing the query's deadline.
    private static async Task<string> ReadResponseContentAsync(HttpClient client, HttpContent content, CancellationToken token) {
        var bytes = await Helpers.BoundedHttpContentReader.ReadAsync(content,
            (int)Math.Min(client.MaxResponseContentBufferSize, int.MaxValue), token).ConfigureAwait(false);
        using var buffered = new ByteArrayContent(bytes);
        buffered.Headers.ContentType = content.Headers.ContentType;
        return await buffered.ReadAsStringAsync().ConfigureAwait(false);
    }
}
