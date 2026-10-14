using DomainDetective.Narratives;
using DomainDetective.Views;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public class TestAutodiscoverBodyEvidence {
    [Fact]
    public async Task OversizedUnknownLengthBodyIsBoundedAndFallbackContinues() {
        var stream = new CountedStream(new byte[4096]);
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            MaxResponseBodyBytes = 1024,
            HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(
                Interlocked.Increment(ref calls) == 1
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamBody(stream) }
                    : Response(TestAutodiscoverAttemptBoundaries.RecognizedError)))
        };
        await analysis.Analyze("example.test", new InternalLogger());
        Assert.Equal(1025, stream.BytesRead);
        Assert.Equal(2, calls);
        Assert.False(analysis.Endpoints[0].DiscoverySucceeded);
        Assert.Equal("body", Assert.Single(analysis.Endpoints[0].Requests).FailureStage);
        Assert.True(analysis.Endpoints[1].DiscoverySucceeded);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BodyReadHonorsEndpointDeadlineAndCallerCancellation(bool cancelCaller) {
        using var caller = new CancellationTokenSource();
        var stream = new BlockingStream();
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            Timeout = cancelCaller ? TimeSpan.FromSeconds(10) : TimeSpan.FromMilliseconds(500),
            AnalysisTimeout = TimeSpan.FromSeconds(15),
            HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(
                Interlocked.Increment(ref calls) == 1
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamBody(stream) }
                    : Response(TestAutodiscoverAttemptBoundaries.RecognizedError)))
        };
        Task run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        Assert.Same(stream.Entered.Task, await Task.WhenAny(stream.Entered.Task, Task.Delay(5000)));
        if (cancelCaller) {
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
            Assert.Equal(1, calls);
            Assert.DoesNotContain(analysis.Assessments, item => item.Code == AutodiscoverCodes.CheckFailed);
        } else {
            await run;
            Assert.Equal(2, calls);
            Assert.Equal("body", Assert.Single(analysis.Endpoints[0].Requests).FailureStage);
            Assert.True(analysis.Endpoints[1].DiscoverySucceeded);
        }
        Assert.True(stream.Disposed);
    }

    [Fact]
    public async Task CallerCancellationDuringPostStopsRemainingEndpoints() {
        using var caller = new CancellationTokenSource();
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        int calls = 0;
        var analysis = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new Handler(async (request, token) => {
                Interlocked.Increment(ref calls);
                if (request.Method == HttpMethod.Get) return new HttpResponseMessage(HttpStatusCode.MethodNotAllowed);
                entered.TrySetResult(true);
                await Task.Delay(System.Threading.Timeout.Infinite, token);
                return Response(TestAutodiscoverAttemptBoundaries.RecognizedError);
            })
        };
        Task run = analysis.Analyze("example.test", new InternalLogger(), caller.Token);
        Assert.Same(entered.Task, await Task.WhenAny(entered.Task, Task.Delay(5000)));
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        Assert.Equal(2, calls);
    }

    [Fact]
    public async Task JsonCandidateWithoutXmlConfirmationDoesNotReportDiscoverySuccess() {
        var http = new AutodiscoverHttpAnalysis {
            HttpHandlerFactory = () => new Handler((request, _) => Task.FromResult(
                request.RequestUri!.AbsolutePath.Contains(".json")
                    ? Response("{\"Url\":\"https://mail.example.test/autodiscover/autodiscover.xml\"}")
                    : new HttpResponseMessage(HttpStatusCode.NotFound)))
        };
        await http.Analyze("example.test", new InternalLogger());
        Assert.Contains(http.Endpoints, item => item.JsonValid);
        Assert.DoesNotContain(http.Endpoints, item => item.DiscoverySucceeded);
        var dns = new AutodiscoverAnalysis(); dns.SetHttpEndpoints(http.Endpoints);
        var info = Converters.Convert(dns);
        Assert.False(info.XmlValidFound);
        Assert.Contains("HTTP fail", info.Summary);
        Assert.Contains(AutodiscoverNarrative.Build(dns).Highlights, item => item.Contains("No Autodiscover endpoint"));
        Assert.DoesNotContain(http.Assessments, item => item.Code == AutodiscoverCodes.EndpointDiscovered);
    }

    [Theory]
    [InlineData("settings", "<Protocol><Type>EXPR</Type><Server>mail.example.test</Server></Protocol>")]
    [InlineData("redirectAddr", "<RedirectAddr>user@example.test</RedirectAddr>")]
    [InlineData("redirectAddr", "<RedirectAddr>user@local</RedirectAddr>")]
    [InlineData("redirectUrl", "<RedirectUrl>https://mail.example.test/autodiscover/autodiscover.xml</RedirectUrl>")]
    public async Task RecognizesOutlookPoxResponseKinds(string action, string detail) {
        string body = "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">"
            + "<Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">"
            + "<Account><AccountType>email</AccountType><Action>" + action + "</Action>" + detail + "</Account></Response></Autodiscover>";
        var analysis = new AutodiscoverHttpAnalysis { HttpHandlerFactory = () => new Handler((_, _) => Task.FromResult(Response(body))) };
        await analysis.Analyze("example.test", new InternalLogger());
        var endpoint = Assert.Single(analysis.Endpoints);
        Assert.True(endpoint.DiscoverySucceeded);
        Assert.Equal(action, endpoint.ServiceResponseType);
    }

    private static HttpResponseMessage Response(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body) };
    private sealed class Handler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _send;
        public Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) => _send = send;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => _send(request, token);
    }
    private sealed class StreamBody : HttpContent {
        private readonly Stream _stream;
        public StreamBody(Stream stream) => _stream = stream;
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new InvalidOperationException("Body must be streamed.");
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult(_stream);
        protected override void Dispose(bool disposing) { if (disposing) _stream.Dispose(); base.Dispose(disposing); }
    }
    private sealed class CountedStream : MemoryStream {
        public int BytesRead { get; private set; }
        public CountedStream(byte[] bytes) : base(bytes) { }
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
            int read = await base.ReadAsync(buffer, offset, count, token); BytesRead += read; return read;
        }
    }
    private sealed class BlockingStream : Stream {
        public TaskCompletionSource<bool> Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Disposed { get; private set; }
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
            Entered.TrySetResult(true); await Task.Delay(System.Threading.Timeout.Infinite, token); return 0;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
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
