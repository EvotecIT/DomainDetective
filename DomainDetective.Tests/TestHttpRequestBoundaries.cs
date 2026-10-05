using System.Net;
using System.Net.Http;
using DomainDetective.Views;
using Xunit;

namespace DomainDetective.Tests;

public class TestHttpRequestBoundaries {
    [Theory]
    [InlineData("/final", true)]
    [InlineData("https://ORIGIN.test:443/final", true)]
    [InlineData("//other.test/final", false)]
    [InlineData("https://origin.test:444/final", false)]
    public async Task RedirectCustomizationIsBoundToOriginalOrigin(string location, bool expectHeaders) {
        var requests = new List<(Uri Uri, bool Cookie, bool Authorization, bool ApiKey)>();
        var analysis = new HttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => {
                requests.Add((request.RequestUri!, request.Headers.Contains("Cookie"),
                    request.Headers.Contains("Authorization"), request.Headers.Contains("X-Api-Key")));
                var response = new HttpResponseMessage(requests.Count == 1 ? HttpStatusCode.Found : HttpStatusCode.OK) {
                    RequestMessage = request, Content = new StringContent("done")
                };
                if (requests.Count == 1) response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);
                return response;
            })
        };
        var options = Credentials();
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), captureBody: true, requestOptions: options);

        Assert.True(analysis.IsReachable);
        Assert.Equal("done", analysis.Body);
        Assert.Equal(2, requests.Count);
        Assert.True(requests[0].Cookie && requests[0].Authorization && requests[0].ApiKey);
        Assert.Equal(expectHeaders, requests[1].Cookie);
        Assert.Equal(expectHeaders, requests[1].Authorization);
        Assert.Equal(expectHeaders, requests[1].ApiKey);
        Assert.Equal("secret", options.Headers["X-Api-Key"]);
    }

    [Fact]
    public async Task DoesNotSendDowngradedRequest() {
        var count = 0;
        var analysis = new HttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => {
                count++;
                var response = new HttpResponseMessage(HttpStatusCode.Found) { RequestMessage = request };
                response.Headers.Location = new Uri("http://origin.test/final");
                return response;
            })
        };
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), requestOptions: Credentials());
        Assert.Equal(1, count);
        Assert.False(analysis.IsReachable);
        Assert.NotNull(analysis.FailureReason);
    }

    [Fact]
    public async Task HeaderOnlyAnalysisDoesNotReadBody() {
        var content = new TrackingContent(4096);
        var analysis = StubAnalysis(content);
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger());
        Assert.True(analysis.IsReachable);
        Assert.Equal(0, content.BytesRead);
        Assert.Null(analysis.Body);
        Assert.True(content.Disposed);
    }

    [Fact]
    public async Task CallerCancellationPropagates() {
        using var cancellation = new CancellationTokenSource();
        var analysis = new HttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((_, _) => {
                cancellation.Cancel();
                throw new OperationCanceledException(cancellation.Token);
            })
        };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => analysis.AnalyzeUrl(
            "https://origin.test/", false, new InternalLogger(), cancellationToken: cancellation.Token));
    }

    [Fact]
    public async Task FailedReuseClearsPreviousSuccess() {
        var analysis = StubAnalysis(new StringContent("done"));
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), captureBody: true);
        Assert.Equal(200, analysis.StatusCode);
        analysis.HttpHandlerFactory = () => new HttpStubMessageHandler((_, _) => throw new HttpRequestException("offline"));
        await analysis.AnalyzeUrl("https://other.test/", false, new InternalLogger());
        Assert.False(analysis.IsReachable);
        Assert.Null(analysis.StatusCode);
        Assert.Null(analysis.ProtocolVersion);
        Assert.Null(analysis.Body);
        Assert.All(analysis.Assessments, entry => Assert.Equal("https://other.test/", entry.Target));
    }

    [Fact]
    public async Task TextualHttpHintDoesNotFailSecurityGrade() {
        var analysis = new HttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => {
                var response = new HttpResponseMessage(HttpStatusCode.OK) {
                    RequestMessage = request, Content = new StringContent("<p>See http://example.test/docs</p>")
                };
                foreach (var name in new[] { "Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy",
                    "X-Content-Type-Options", "X-Frame-Options", "Permissions-Policy" }) {
                    response.Headers.TryAddWithoutValidation(name, "test");
                }
                return response;
            })
        };
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), collectHeaders: true, captureBody: true);
        Assert.True(analysis.MixedContentDetected);
        Assert.Equal(GradeLevel.A, Converters.Convert(analysis).Grade);
        Assert.DoesNotContain(analysis.Assessments, entry => entry.Code == HttpCodes.MixedContent);
        Assert.DoesNotContain(Converters.Convert(analysis).Positives, entry => entry.Code == HttpCodes.MixedContent);
    }

    [Theory]
    [InlineData(32, false)]
    [InlineData(4096, true)]
    public async Task BodyCaptureIsBoundedAndHashesOnlyCompleteEvidence(int length, bool truncated) {
        var content = new TrackingContent(length);
        var analysis = StubAnalysis(content);
        analysis.MaxBodyBytes = 32;
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), captureBody: true);
        Assert.True(analysis.IsReachable);
        Assert.Equal(32, analysis.BodyLength);
        Assert.Equal(truncated, analysis.BodyTruncated);
        Assert.Equal(truncated, analysis.BodySha256 == null);
        Assert.InRange(content.BytesRead, 32, 33);
        Assert.True(content.Disposed);
        Assert.Equal(truncated, Converters.Convert(analysis).BodyTruncated);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BodyReadRespectsCallerCancellationAndAnalysisDeadline(bool cancelCaller) {
        using var cancellation = new CancellationTokenSource();
        var content = new BlockingContent();
        var analysis = StubAnalysis(content);
        analysis.Timeout = cancelCaller ? TimeSpan.FromSeconds(10) : TimeSpan.FromMilliseconds(100);
        if (cancelCaller) cancellation.CancelAfter(TimeSpan.FromMilliseconds(100));
        var run = analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(),
            captureBody: true, cancellationToken: cancellation.Token);
        if (cancelCaller) {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run);
        } else {
            await run;
            Assert.False(analysis.IsReachable);
            Assert.Contains(analysis.Assessments, entry => entry.Code == HttpCodes.Timeout);
        }
        Assert.True(content.Disposed);
    }

    [Fact]
    public async Task LaterForeignHopsCannotAcquireOriginalCredentials() {
        var seen = new List<bool>();
        var analysis = new HttpAnalysis {
            HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => {
                seen.Add(request.Headers.Contains("Cookie") || request.Headers.Contains("X-Api-Key"));
                var response = new HttpResponseMessage(seen.Count == 3 ? HttpStatusCode.OK : HttpStatusCode.Found);
                if (seen.Count < 3) response.Headers.Location = new Uri("https://other.test/" + seen.Count);
                return response;
            })
        };
        await analysis.AnalyzeUrl("https://origin.test/", false, new InternalLogger(), requestOptions: Credentials());
        Assert.Equal(new[] { true, false, false }, seen);
    }

    private static HttpRequestOptions Credentials() {
        var options = new HttpRequestOptions { Cookie = "session=secret" };
        options.Headers["cOoKiE"] = "second=secret";
        options.Headers["Authorization"] = "Bearer secret";
        options.Headers["X-Api-Key"] = "secret";
        return options;
    }

    private static HttpAnalysis StubAnalysis(HttpContent content) => new() {
        HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => new HttpResponseMessage(HttpStatusCode.OK) {
            RequestMessage = request, Content = content
        })
    };

    private sealed class TrackingContent : HttpContent {
        private readonly TrackingStream _stream;
        private int _serializedBytes;
        public TrackingContent(int size) { _stream = new TrackingStream(new byte[size]); }
        public int BytesRead => _serializedBytes + _stream.BytesRead;
        public bool Disposed { get; private set; }
        protected override bool TryComputeLength(out long length) { length = _stream.Length; return true; }
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(_stream);
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) {
            _serializedBytes += (int)_stream.Length;
            return _stream.CopyToAsync(stream);
        }
        protected override void Dispose(bool disposing) { Disposed = true; _stream.Dispose(); base.Dispose(disposing); }
    }

    private sealed class BlockingContent : HttpContent {
        public bool Disposed { get; private set; }
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new BlockingStream());
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new InvalidOperationException("Body must be streamed.");
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private sealed class BlockingStream : MemoryStream {
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
            await Task.Delay(System.Threading.Timeout.Infinite, token);
            return 0;
        }
    }

    private sealed class TrackingStream : MemoryStream {
        public TrackingStream(byte[] bytes) : base(bytes) { }
        public int BytesRead { get; private set; }
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken token) {
            var read = await base.ReadAsync(buffer, offset, count, token);
            BytesRead += read;
            return read;
        }
    }
}
