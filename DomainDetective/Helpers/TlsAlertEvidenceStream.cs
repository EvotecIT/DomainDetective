using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Helpers;

/// <summary>Observes only the first TLS record prefix to distinguish an explicit remote version rejection from a local handshake failure.</summary>
/// <remarks>RFC 5246 sections 6.2.1 and 7.2 define the record header and fatal protocol_version alert. Ambiguous or later records remain unknown.</remarks>
internal sealed class TlsAlertEvidenceStream : Stream {
    private readonly Stream _inner;
    private readonly bool _leaveOpen;
    private readonly byte[] _prefix = new byte[7];
    private int _received;

    internal TlsAlertEvidenceStream(Stream inner, bool leaveOpen = false) {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _leaveOpen = leaveOpen;
    }

    internal bool SawProtocolVersionRejection => _received == _prefix.Length &&
        _prefix[0] == 21 && _prefix[1] == 3 && _prefix[2] <= 3 &&
        _prefix[3] == 0 && _prefix[4] == 2 && _prefix[5] == 2 && _prefix[6] == 70;

    private void Capture(byte[] buffer, int offset, int count) {
        int take = Math.Min(count, _prefix.Length - _received);
        if (take <= 0) { return; }
        Buffer.BlockCopy(buffer, offset, _prefix, _received, take);
        _received += take;
    }

    public override int Read(byte[] buffer, int offset, int count) {
        int read = _inner.Read(buffer, offset, count);
        Capture(buffer, offset, read);
        return read;
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) {
        int read = await _inner.ReadAsync(buffer, offset, count, cancellationToken).ConfigureAwait(false);
        Capture(buffer, offset, read);
        return read;
    }

    public override bool CanRead => _inner.CanRead;
    public override bool CanWrite => _inner.CanWrite;
    public override bool CanSeek => _inner.CanSeek;
    public override bool CanTimeout => _inner.CanTimeout;
    public override long Length => _inner.Length;
    public override long Position { get => _inner.Position; set => _inner.Position = value; }
    public override int ReadTimeout { get => _inner.ReadTimeout; set => _inner.ReadTimeout = value; }
    public override int WriteTimeout { get => _inner.WriteTimeout; set => _inner.WriteTimeout = value; }
    public override void Flush() => _inner.Flush();
    public override Task FlushAsync(CancellationToken cancellationToken) => _inner.FlushAsync(cancellationToken);
    public override long Seek(long offset, SeekOrigin origin) => _inner.Seek(offset, origin);
    public override void SetLength(long value) => _inner.SetLength(value);
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        _inner.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing) {
        if (disposing && !_leaveOpen) { _inner.Dispose(); }
        base.Dispose(disposing);
    }
}
