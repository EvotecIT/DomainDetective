using System.Net;
using System.Net.Http;
using Xunit;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestHttpTransportBoundaries {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ActualHttp11RedirectCannotBypassOriginFiltering(bool wrappedHandler) {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var source = StartListener(out var sourceUrl);
        using var destination = StartListener(out var destinationUrl);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var sourceTask = ReceiveAsync(source, cancellation.Token, destinationUrl);
        var destinationTask = ReceiveAsync(destination, cancellation.Token);
        try {
            var analysis = new HttpAnalysis { RequestVersion = HttpVersion.Version11 };
            if (wrappedHandler) analysis.HttpHandlerFactory = () => new PassThroughHandler(new HttpClientHandler { AllowAutoRedirect = true, UseProxy = false });
            var options = new HttpRequestOptions { Cookie = "session=secret" };
            options.Headers["X-Api-Key"] = "secret";
            await analysis.AnalyzeUrl(sourceUrl, false, new InternalLogger(), requestOptions: options, cancellationToken: cancellation.Token);
            Assert.True(analysis.IsReachable);
            Assert.Equal(2, analysis.VisitedUrls.Count);
            Assert.Equal((true, true), await sourceTask);
            Assert.Equal((false, false), await destinationTask);
        } finally {
            cancellation.Cancel();
            source.Stop();
            destination.Stop();
            await IgnoreStoppedAsync(sourceTask, destinationTask);
        }
    }

    [Fact]
    public async Task ExternalVisualAssetAndItsRedirectDoNotReceivePageCredentials() {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var assetServer = StartListener(out var assetUrl);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var captured = new List<(bool Cookie, bool ApiKey)>();
        var serverTask = Task.Run(async () => {
            captured.Add(await ReceiveAsync(assetServer, cancellation.Token, assetUrl + "final"));
            captured.Add(await ReceiveAsync(assetServer, cancellation.Token));
        });
        try {
            var options = new TyposquattingVisualSimilarityOptions {
                Enabled = true, EnableBrowserCapture = false, EnableStaticAssetCapture = true, MaxAssetsPerPage = 1,
                PageHttpOverride = async (url, token) => {
                    var page = new HttpAnalysis {
                        HttpHandlerFactory = () => new HttpStubMessageHandler((request, _) => new HttpResponseMessage(HttpStatusCode.OK) {
                            RequestMessage = request, Content = new StringContent($"<link rel='icon' href='{assetUrl}image'>")
                        })
                    };
                    await page.AnalyzeUrl(url, false, new InternalLogger(), captureBody: true, cancellationToken: token);
                    return page;
                }
            };
            options.HttpRequestOptions.Cookie = "session=secret";
            options.HttpRequestOptions.Headers["X-Api-Key"] = "secret";
            await TyposquattingVisualSimilarityAnalyzer.BuildProfileAsync("origin.test", options, cancellation.Token);
            await serverTask;
            Assert.Equal(new[] { (false, false), (false, false) }, captured);
        } finally {
            cancellation.Cancel();
            assetServer.Stop();
            await IgnoreStoppedAsync(serverTask);
        }
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ServerCookieProgressionRespectsHandlerOptOut(bool useCookies) {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var server = StartListener(out var url);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var peer = Task.Run(async () => {
            var initial = await server.GetContextAsync().WaitWithCancellation(cancellation.Token);
            initial.Response.AddHeader("Set-Cookie", "issued=server; Path=/");
            initial.Response.StatusCode = 302;
            initial.Response.RedirectLocation = url + "final";
            initial.Response.Close();
            var final = await server.GetContextAsync().WaitWithCancellation(cancellation.Token);
            var cookie = final.Request.Cookies["issued"]?.Value;
            final.Response.Close();
            return cookie;
        });
        try {
            var analysis = new HttpAnalysis {
                RequestVersion = HttpVersion.Version11,
                HttpHandlerFactory = () => new HttpClientHandler { UseCookies = useCookies, UseProxy = false }
            };
            await analysis.AnalyzeUrl(url, false, new InternalLogger(), cancellationToken: cancellation.Token);
            Assert.True(analysis.IsReachable);
            Assert.Equal(useCookies ? "server" : null, await peer);
        } finally {
            cancellation.Cancel(); server.Stop(); await IgnoreStoppedAsync(peer);
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task StaticScanKeepsDocumentSizeSeparateFromCapturedPrefix(bool chunked) {
        Skip.If(!HttpListener.IsSupported, "HttpListener not supported");
        using var server = StartListener(out var url);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        const int length = 2 * 1024 * 1024 + 17;
        var peer = Task.Run(async () => {
            var context = await server.GetContextAsync().WaitWithCancellation(cancellation.Token);
            context.Response.SendChunked = chunked;
            if (!chunked) context.Response.ContentLength64 = length;
            try { await context.Response.OutputStream.WriteAsync(new byte[length], 0, length, cancellation.Token); }
            catch (IOException) { /* The bounded reader may close its body stream early. */ }
            finally { context.Response.Close(); }
        });
        try {
            var scan = new WebStaticScanAnalysis { LinkOnly = true, FollowLinks = false };
            await scan.Analyze(url, new InternalLogger(), cancellation.Token);
            var request = Assert.Single(scan.Requests);
            Assert.True(request.BodyTruncated);
            Assert.Equal(2 * 1024 * 1024, request.CapturedBodyLength);
            Assert.Equal(chunked ? (long?)null : length, request.ContentLength);
            Assert.Equal(chunked ? 0 : length, scan.Hosts[new Uri(url).Host].Bytes);
            await peer;
        } finally {
            cancellation.Cancel(); server.Stop(); await IgnoreStoppedAsync(peer);
        }
    }

    private static HttpListener StartListener(out string url) {
        var port = PortHelper.GetFreePort();
        var listener = new HttpListener();
        url = $"http://localhost:{port}/";
        listener.Prefixes.Add(url);
        try { listener.Start(); }
        catch { listener.Close(); throw; }
        finally { PortHelper.ReleasePort(port); }
        return listener;
    }

    private static async Task<(bool Cookie, bool ApiKey)> ReceiveAsync(HttpListener listener, CancellationToken token, string? redirect = null) {
        var context = await listener.GetContextAsync().WaitWithCancellation(token);
        var captured = (!string.IsNullOrEmpty(context.Request.Headers["Cookie"]), !string.IsNullOrEmpty(context.Request.Headers["X-Api-Key"]));
        context.Response.StatusCode = redirect == null ? 200 : 302;
        if (redirect != null) context.Response.RedirectLocation = redirect;
        context.Response.ContentLength64 = 0;
        context.Response.Close();
        return captured;
    }

    private static async Task IgnoreStoppedAsync(params Task[] tasks) {
        foreach (var task in tasks) {
            try { await task; }
            catch (OperationCanceledException) { }
            catch (HttpListenerException) { }
            catch (ObjectDisposedException) { }
        }
    }
}
