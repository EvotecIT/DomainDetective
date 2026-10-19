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
        byte[] bytes;
        try {
            bytes = await Helpers.BoundedHttpContentReader.ReadAsync(content,
                (int)Math.Min(client.MaxResponseContentBufferSize, int.MaxValue), token).ConfigureAwait(false);
        } catch (System.IO.IOException error) {
            token.ThrowIfCancellationRequested();
            // HttpClient's buffered completion exposes failed body transfers as
            // HTTP failures. Preserve that contract after moving body reads here.
            throw new HttpRequestException("Error while reading CT response content.", error);
        }
        using var buffered = new ByteArrayContent(bytes);
        buffered.Headers.ContentType = content.Headers.ContentType;
        return await buffered.ReadAsStringAsync().ConfigureAwait(false);
    }
}
