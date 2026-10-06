using DomainDetective.Helpers;
using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestBoundedHttpContentReader {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OversizedEvidenceCannotBecomeAValidPrefix(bool declaredLength) {
        using var content = new StreamContent(new MemoryStream(new byte[17]));
        if (declaredLength) content.Headers.ContentLength = 17;
        else content.Headers.ContentLength = null;
        await Assert.ThrowsAsync<HttpRequestException>(() => BoundedHttpContentReader.ReadAsync(content, 16, CancellationToken.None));
    }

    [Fact]
    public async Task CompleteEvidenceExactlyAtTheBoundIsReturned() {
        byte[] bytes = { 1, 2, 3, 4 };
        using var content = new ByteArrayContent(bytes);
        Assert.Equal(bytes, await BoundedHttpContentReader.ReadAsync(content, bytes.Length, CancellationToken.None));
    }

    [Fact]
    public async Task CancellationReleasesAStreamWhoseReadIgnoresTheToken() {
        var stream = new HeldReadStream();
        using var content = new StreamContent(stream);
        using var cancellation = new CancellationTokenSource();
        Task<byte[]> reading = BoundedHttpContentReader.ReadAsync(content, 16, cancellation.Token);
        await stream.Entered.Task;
        cancellation.Cancel();
        try {
            Assert.Same(reading, await Task.WhenAny(reading, Task.Delay(TimeSpan.FromSeconds(5))));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reading);
            Assert.True(stream.Disposed);
        } finally {
            stream.Dispose();
        }
    }

    private sealed class HeldReadStream : Stream {
        internal readonly TaskCompletionSource<bool> Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<int> _read = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Disposed;
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) { Entered.TrySetResult(true); return _read.Task; }
        protected override void Dispose(bool disposing) { Disposed = true; _read.TrySetException(new ObjectDisposedException(nameof(HeldReadStream))); base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
