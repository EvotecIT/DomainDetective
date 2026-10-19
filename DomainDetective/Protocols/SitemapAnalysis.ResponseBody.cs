using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class SitemapAnalysis {
    private static async Task<string?> ReadLimitedBodyAsync(HttpContent content, int maxCharacters, bool decompressGzip, CancellationToken cancellationToken) {
        cancellationToken.ThrowIfCancellationRequested();
        // HttpClient completes at response headers. Disposing the owned content also
        // interrupts legacy StreamReader/GZip reads that cannot receive a token.
        using var cancellation = cancellationToken.Register(() => content.Dispose());
        try {
            return await ReadLimitedBodyCoreAsync(content, maxCharacters, decompressGzip, cancellationToken).ConfigureAwait(false);
        } catch (Exception) when (cancellationToken.IsCancellationRequested) {
            cancellationToken.ThrowIfCancellationRequested();
            throw;
        }
    }

    private static async Task<string?> ReadLimitedBodyCoreAsync(HttpContent content, int maxCharacters, bool decompressGzip, CancellationToken cancellationToken) {
        var limit = Math.Max(1024, maxCharacters);

        Encoding encoding;
        try {
            var charset = content.Headers.ContentType?.CharSet;
            var trimmedCharset = string.Empty;
            if (!string.IsNullOrWhiteSpace(charset)) {
                trimmedCharset = charset!.Trim('"');
            }

            encoding = string.IsNullOrWhiteSpace(trimmedCharset)
                ? Encoding.UTF8
                : Encoding.GetEncoding(trimmedCharset);
        } catch (ArgumentException) {
            encoding = Encoding.UTF8;
        }

#if NET8_0_OR_GREATER
        using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
#else
        using var stream = await content.ReadAsStreamAsync().ConfigureAwait(false);
#endif
        using var readableStream = await CreateReadableBodyStreamAsync(stream, decompressGzip, cancellationToken).ConfigureAwait(false);
        using var reader = new StreamReader(readableStream, encoding, detectEncodingFromByteOrderMarks: true, bufferSize: 8192);
        var builder = new StringBuilder(Math.Min(limit, 8192));
        var buffer = new char[Math.Min(limit, 8192)];

        while (builder.Length < limit) {
            cancellationToken.ThrowIfCancellationRequested();
            var remaining = limit - builder.Length;
#if NET8_0_OR_GREATER
            var read = await reader.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, remaining)), cancellationToken).ConfigureAwait(false);
#else
            var read = await reader.ReadAsync(buffer, 0, Math.Min(buffer.Length, remaining)).ConfigureAwait(false);
#endif
            if (read == 0) {
                break;
            }

            builder.Append(buffer, 0, read);
        }

        return builder.ToString();
    }

    private static async Task<Stream> CreateReadableBodyStreamAsync(Stream stream, bool decompressGzip, CancellationToken cancellationToken) {
        if (decompressGzip) {
            return new GZipStream(stream, CompressionMode.Decompress);
        }

        var prefix = new byte[2];
        var read = 0;
        while (read < prefix.Length) {
            cancellationToken.ThrowIfCancellationRequested();
            var count = await stream.ReadAsync(prefix, read, prefix.Length - read, cancellationToken).ConfigureAwait(false);
            if (count == 0) {
                break;
            }

            read += count;
        }

        var prefixedStream = new PrefixedStream(prefix, read, stream);
        if (read >= 2 && prefix[0] == 0x1f && prefix[1] == 0x8b) {
            return new GZipStream(prefixedStream, CompressionMode.Decompress);
        }

        return prefixedStream;
    }

    private static bool HasGzipHeader(HttpContent content) {
        if (content.Headers.ContentEncoding.Any(value => value.Equals("gzip", StringComparison.OrdinalIgnoreCase))) {
            return true;
        }

        return HasGzipMediaType(content.Headers.ContentType?.MediaType);
    }

    private static bool HasGzipMediaType(string? mediaType) {
        if (string.IsNullOrWhiteSpace(mediaType)) {
            return false;
        }

        return mediaType!.IndexOf("gzip", StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private sealed class PrefixedStream : Stream {
        private readonly byte[] _prefix;
        private readonly int _prefixLength;
        private readonly Stream _inner;
        private int _prefixOffset;

        public PrefixedStream(byte[] prefix, int prefixLength, Stream inner) {
            _prefix = prefix;
            _prefixLength = prefixLength;
            _inner = inner;
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() {
        }

        public override int Read(byte[] buffer, int offset, int count) {
            var copied = CopyPrefix(buffer, offset, count);
            if (copied == count) {
                return copied;
            }

            return copied + _inner.Read(buffer, offset + copied, count - copied);
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
            var copied = CopyPrefix(buffer, offset, count);
            if (copied == count) {
                return copied;
            }

            return copied + await _inner.ReadAsync(buffer, offset + copied, count - copied, cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) {
            throw new NotSupportedException();
        }

        public override void SetLength(long value) {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count) {
            throw new NotSupportedException();
        }

        private int CopyPrefix(byte[] buffer, int offset, int count) {
            if (_prefixOffset >= _prefixLength || count == 0) {
                return 0;
            }

            var available = _prefixLength - _prefixOffset;
            var copy = Math.Min(available, count);
            Buffer.BlockCopy(_prefix, _prefixOffset, buffer, offset, copy);
            _prefixOffset += copy;
            return copy;
        }
    }

}
