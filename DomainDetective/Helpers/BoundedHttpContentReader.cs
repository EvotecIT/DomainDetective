using DnsClientX;
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Reads complete evidence within a strict byte bound and releases its stream on cancellation.</summary>
internal static class BoundedHttpContentReader {
    internal static async Task<byte[]> ReadAsync(HttpContent content, int maxBytes, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        if (content.Headers.ContentLength is long length && length > maxBytes) throw new HttpRequestException("Evidence exceeds the response byte limit.");
        using Stream stream = await content.ReadAsStreamAsync().WaitWithCancellation(cancellationToken).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[Math.Min(81920, maxBytes + 1)];
        while (true) {
            Task<int> reading = stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
            int read;
            try {
                read = await reading.WaitWithCancellation(cancellationToken).ConfigureAwait(false);
            } catch (OperationCanceledException) {
                _ = reading.ContinueWith(static task => { _ = task.Exception; }, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                throw;
            }
            if (read == 0) return output.ToArray();
            if (output.Length + read > maxBytes) throw new HttpRequestException("Evidence exceeds the response byte limit.");
            output.Write(buffer, 0, read);
        }
    }
}
