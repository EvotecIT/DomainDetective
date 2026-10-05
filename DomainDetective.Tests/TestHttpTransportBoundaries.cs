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
