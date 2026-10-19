using System.Net;
using System.Net.Http;

namespace DomainDetective.Tests;

[Collection("CtSharedState")]
public class TestCtSourceScheduling {
    public TestCtSourceScheduling() => CtLogAggregator.ResetSharedStateForTests();

    [Fact]
    public async Task IndependentSourcesStartBeforeSlowSourceFinishesAndKeepSourceOrder() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var aggregator = new CtLogAggregator {
            MinimumRequestSpacing = TimeSpan.Zero,
            HttpHandlerFactory = () => new Handler(async (request, token) => {
                bool first = request.RequestUri!.Host.StartsWith("first.", StringComparison.Ordinal);
                if (first) { await release.Task.WaitWithCancellation(token); }
                else { secondEntered.TrySetResult(true); }
                return new HttpResponseMessage(HttpStatusCode.OK) {
                    Content = new StringContent(first ? "[{\"id\":1}]" : "[{\"id\":2}]")
                };
            })
        };
        aggregator.ApiTemplates.Clear();
        string identity = Guid.NewGuid().ToString("N");
        aggregator.ApiTemplates.Add("https://first." + identity + ".example.test/{0}");
        aggregator.ApiTemplates.Add("https://second." + identity + ".example.test/{0}");
        var run = aggregator.QueryWithResultAsync("synthetic", guard.Token);
        try {
            await secondEntered.Task.WaitWithCancellation(guard.Token);
            Assert.False(run.IsCompleted);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) when (guard.IsCancellationRequested) { } }
        var result = await run;
        Assert.True(result.Complete);
        Assert.Equal(new[] { 1, 2 }, result.Entries.Select(item => item.GetProperty("id").GetInt32()));
        Assert.Equal(2, result.Sources.Count);
    }

    [Fact]
    public async Task TransientStatusRetriesWithoutBufferingItsUnneededBody() {
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var body = new HeldContent(release.Task);
        int attempts = 0;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var aggregator = new CtLogAggregator {
            MinimumRequestSpacing = TimeSpan.Zero,
            RetryDelay = TimeSpan.Zero,
            HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(
                Interlocked.Increment(ref attempts) == 1
                    ? new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = body }
                    : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("[]") }))
        };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}");
        var run = aggregator.QueryWithResultAsync("synthetic", guard.Token);
        try {
            var result = await run.WaitWithCancellation(guard.Token);
            Assert.True(result.Complete);
            Assert.Equal(2, attempts);
            Assert.Equal(0, body.Reads);
            Assert.True(body.Disposed);
        } finally { release.TrySetResult(true); try { await run; } catch (OperationCanceledException) { } }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
    }

    [Fact]
    public async Task TransientSuccessfulBodyDisconnectRetriesAndRetainsRecoveredEntries() {
        int attempts = 0;
        var aggregator = new CtLogAggregator {
            MinimumRequestSpacing = TimeSpan.Zero, RetryDelay = TimeSpan.Zero,
            HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) {
                Content = Interlocked.Increment(ref attempts) == 1
                    ? new StreamContent(new DisconnectedStream()) : new StringContent("[{\"id\":7}]")
            }))
        };
        aggregator.ApiTemplates.Clear();
        aggregator.ApiTemplates.Add("https://" + Guid.NewGuid().ToString("N") + ".example.test/{0}");
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await aggregator.QueryWithResultAsync("synthetic", guard.Token);
        Assert.True(result.Complete);
        Assert.Equal(7, Assert.Single(result.Entries).GetProperty("id").GetInt32());
        Assert.Equal(2, attempts);
    }

    private sealed class DisconnectedStream : Stream {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("Synthetic disconnect.");
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) => Task.FromException<int>(new IOException("Synthetic disconnect."));
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class HeldContent(Task release) : HttpContent {
        internal int Reads;
        internal bool Disposed;
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context) {
            Interlocked.Increment(ref Reads);
            await release;
        }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
