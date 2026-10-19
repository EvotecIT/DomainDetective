using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestHttpProbePooling {
    [Fact]
    public async Task AnonymousTransportIsReusedWhileCookiesAndCustomRequestsStayIsolated() {
        var reservation = new TcpListener(IPAddress.Loopback, 0);
        reservation.Start();
        int port = ((IPEndPoint)reservation.LocalEndpoint).Port;
        reservation.Stop();
        string origin = $"http://127.0.0.1:{port}";
        using var listener = new HttpListener();
        listener.Prefixes.Add(origin + "/");
        listener.Start();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var observations = new List<(int Port, string? Cookie, string? Custom)>();
        var server = Task.Run(async () => {
            for (int index = 0; index < 4; index++) {
                var context = await listener.GetContextAsync().WaitWithCancellation(guard.Token);
                observations.Add((context.Request.RemoteEndPoint.Port, context.Request.Headers["Cookie"], context.Request.Headers["X-Probe"]));
                if (index == 0) {
                    context.Response.StatusCode = 302;
                    context.Response.RedirectLocation = origin + "/final";
                    context.Response.Headers.Add("Set-Cookie", "session=one; Path=/");
                }
                var body = Encoding.UTF8.GetBytes("<html></html>");
                context.Response.ContentLength64 = body.Length;
                await context.Response.OutputStream.WriteAsync(body, 0, body.Length, guard.Token);
                context.Response.Close();
            }
        });
        try {
            var first = new HttpAnalysis();
            await first.AnalyzeUrl(origin + "/seed", checkHsts: true, logger: new InternalLogger(), captureBody: true, cancellationToken: guard.Token);
            var second = new HttpAnalysis();
            await second.AnalyzeUrl(origin + "/again", checkHsts: true, logger: new InternalLogger(), captureBody: true, cancellationToken: guard.Token);
            var custom = new HttpRequestOptions { Cookie = "custom=two" };
            custom.Headers["X-Probe"] = "custom";
            var third = new HttpAnalysis();
            await third.AnalyzeUrl(origin + "/custom", checkHsts: true, logger: new InternalLogger(), captureBody: true, cancellationToken: guard.Token, requestOptions: custom);
            await server;
            Assert.True(first.IsReachable);
            Assert.True(second.IsReachable);
            Assert.True(third.IsReachable);
            Assert.Equal(4, observations.Count);
            Assert.Contains("session=one", observations[1].Cookie);
            Assert.True(string.IsNullOrEmpty(observations[2].Cookie));
            Assert.Equal(observations[1].Port, observations[2].Port);
            Assert.Equal("custom=two", observations[3].Cookie);
            Assert.Equal("custom", observations[3].Custom);
            Assert.NotEqual(observations[2].Port, observations[3].Port);
        } finally {
            guard.Cancel();
            listener.Close();
            try { await server; }
            catch (OperationCanceledException) { }
            catch (HttpListenerException) { }
            catch (ObjectDisposedException) { }
        }
    }
}
