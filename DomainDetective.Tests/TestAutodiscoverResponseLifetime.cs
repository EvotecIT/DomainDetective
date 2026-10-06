using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverResponseLifetime {
    [Theory]
    [InlineData("utf-8", false)]
    [InlineData("utf-8", true)]
    [InlineData("utf-16", false)]
    public async Task BomEncodedServiceResponseRemainsRecognized(string charset, bool declareCharset) {
        Encoding encoding = Encoding.GetEncoding(charset);
        byte[] bytes = encoding.GetPreamble();
        byte[] body = encoding.GetBytes(TestAutodiscoverAttemptBoundaries.RecognizedError);
        Array.Resize(ref bytes, bytes.Length + body.Length);
        Array.Copy(body, 0, bytes, bytes.Length - body.Length, body.Length);
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new Handler((_, _) => {
                var content = new ByteArrayContent(bytes);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/xml");
                if (declareCharset) content.Headers.ContentType.CharSet = charset;
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
            })
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.True(Assert.Single(analysis.Endpoints).DiscoverySucceeded);
    }

    [Theory]
    [InlineData("caller")]
    [InlineData("endpoint")]
    [InlineData("overall")]
    public async Task NonCooperativeBodyIsAbortedAtEveryDeadline(string mode) {
        using var caller = new CancellationTokenSource();
        var stream = new FrameworkLikeStream();
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            Timeout = mode == "endpoint" ? TimeSpan.FromMilliseconds(500) : TimeSpan.FromSeconds(15),
            AnalysisTimeout = mode == "overall" ? TimeSpan.FromMilliseconds(500) : TimeSpan.FromSeconds(20),
            HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(
                Interlocked.Increment(ref calls) == 1
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(stream) }
                    : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(TestAutodiscoverAttemptBoundaries.RecognizedError) }))
        };
        Task run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        try {
            Assert.Same(stream.Entered.Task, await Task.WhenAny(stream.Entered.Task, Task.Delay(5000)));
            if (mode == "caller") caller.Cancel();
            Assert.Same(run, await Task.WhenAny(run, Task.Delay(3000)));
            if (mode == "caller") {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
                Assert.Equal(1, calls);
                Assert.DoesNotContain(analysis.Assessments, item => item.Code == AutodiscoverCodes.CheckFailed);
            } else {
                await run;
                Assert.Equal("body", Assert.Single(analysis.Endpoints[0].Requests).FailureStage);
                if (mode == "endpoint") Assert.True(analysis.Endpoints[1].DiscoverySucceeded);
                else { Assert.True(analysis.BudgetExhausted); Assert.Equal(1, calls); }
            }
            Assert.True(stream.Disposed);
            Assert.True(stream.ReadCompletion.Task.IsCompleted);
        } finally {
            stream.Dispose();
            try { await run; } catch (OperationCanceledException) { }
        }
    }

    private sealed class Handler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        public Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => _send(request, token);
    }
    private sealed class FrameworkLikeStream : Stream {
        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<int> ReadCompletion { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Disposed { get; private set; }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
            token.ThrowIfCancellationRequested(); // Framework checks only before starting an asynchronous read.
            Entered.TrySetResult(true);
            return ReadCompletion.Task;
        }
        protected override void Dispose(bool disposing) { Disposed = true; ReadCompletion.TrySetResult(0); base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
