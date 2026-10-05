using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class HttpAnalysis {
    /// <summary>Maximum response-body bytes captured. Defaults to 2 MiB; must be positive.</summary>
    public int MaxBodyBytes { get; set; } = 2 * 1024 * 1024;

    /// <summary>True when the captured body is a prefix. Its SHA-256 is then unavailable.</summary>
    public bool BodyTruncated { get; private set; }

    private async Task CaptureBodyAsync(HttpContent content, CancellationToken cancellationToken) {
#if NET8_0_OR_GREATER
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#else
        using var stream = await content.ReadAsStreamAsync().WaitWithCancellation(cancellationToken).ConfigureAwait(false);
#endif
        using var buffer = new MemoryStream(Math.Min(MaxBodyBytes, 8192));
        var chunk = new byte[8192];
        while (true) {
            var remaining = MaxBodyBytes - (int)buffer.Length;
            var count = remaining < chunk.Length ? remaining + 1 : chunk.Length;
            var read = await stream.ReadAsync(chunk, 0, count, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;
            buffer.Write(chunk, 0, Math.Min(read, remaining));
            if (read > remaining) {
                BodyTruncated = true;
                break;
            }
        }
        var bytes = buffer.ToArray();
        BodyLength = bytes.Length;
        if (!BodyTruncated) {
            using var sha = SHA256.Create();
            BodySha256 = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
        }
        Encoding encoding;
        try {
            var charset = content.Headers.ContentType?.CharSet?.Trim('"');
            encoding = !string.IsNullOrWhiteSpace(charset) ? Encoding.GetEncoding(charset!) : Encoding.UTF8;
        } catch (ArgumentException) { encoding = Encoding.UTF8; }
        Body = encoding.GetString(bytes);
    }
}
