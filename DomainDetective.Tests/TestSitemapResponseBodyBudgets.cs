using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DomainDetective.Tests;

[Collection("HttpListener")]
public class TestSitemapResponseBodyBudgets {
    [Theory]
    [InlineData(0, false, false)]
    [InlineData(3, false, false)]
    [InlineData(0, true, false)]
    [InlineData(0, false, true)]
    [InlineData(3, false, true)]
    [InlineData(0, true, true)]
    public async Task StalledBodyAfterHeadersHonorsDeadlineAndCallerCancellation(int prefixLength, bool gzip, bool callerCancellation) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var serverGuard = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        using var caller = new CancellationTokenSource();
        var headersSent = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task ServeAsync() {
            using var client = await listener.AcceptTcpClientAsync().WaitWithCancellation(serverGuard.Token);
            using var stream = client.GetStream();
            var request = new StringBuilder();
            var buffer = new byte[1];
            while (!request.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) {
                int read = await stream.ReadAsync(buffer, 0, 1, serverGuard.Token);
                if (read == 0) { throw new IOException("Client closed before sending request headers."); }
                request.Append((char)buffer[0]);
            }
            string headers = "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 4096\r\nConnection: close\r\n" +
                (gzip ? "Content-Encoding: gzip\r\n" : string.Empty) + "\r\n" + "<?x".Substring(0, prefixLength);
            byte[] bytes = Encoding.ASCII.GetBytes(headers);
            await stream.WriteAsync(bytes, 0, bytes.Length, serverGuard.Token);
            headersSent.TrySetResult(true);
            await release.Task.WaitWithCancellation(serverGuard.Token);
        }
        Task server = ServeAsync();
        var analysis = new SitemapAnalysis { HttpHandlerFactory = () => new System.Net.Http.HttpClientHandler { UseProxy = false } };
        Task operation = analysis.AnalyzeAsync($"http://127.0.0.1:{port}/sitemap.xml", options: new SitemapAnalysisOptions {
            AllowHttpFallback = false, CheckCanonical = false,
            AnalysisTimeout = callerCancellation ? TimeSpan.FromSeconds(4) : TimeSpan.FromMilliseconds(500)
        }, cancellationToken: caller.Token);
        try {
            await headersSent.Task.WaitWithCancellation(serverGuard.Token);
            if (callerCancellation) { caller.Cancel(); }
            Assert.Same(operation, await Task.WhenAny(operation, Task.Delay(2500, serverGuard.Token)));
            if (callerCancellation) { await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation); }
            else {
                await operation;
                Assert.False(analysis.AnalysisComplete);
                Assert.Contains(analysis.Assessments, assessment => assessment.Code == "SITEMAP.Analysis.Incomplete");
            }
        } finally {
            release.TrySetResult(true);
            listener.Stop();
            await server;
            try { await operation; } catch (OperationCanceledException) when (caller.IsCancellationRequested) { }
        }
    }
}
