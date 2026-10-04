using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestUptimeProbeContracts {
    [Fact]
    public async Task ReusingProbeClearsPreviousHeadersAndAssessments() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string[]> server = ServeAsync(listener, timeout.Token,
            ("200 OK", "Strict-Transport-Security: max-age=3600\r\n", 0, null, TimeSpan.Zero),
            ("503 Service Unavailable", string.Empty, 0, null, TimeSpan.Zero));
        string url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var probe = new UptimeProbeAnalysis();

        try {
            await probe.ProbeAsync(url, ct: timeout.Token);
            Assert.True(probe.Success);
            Assert.NotEmpty(probe.ImportantHeaders);
            Assert.NotEmpty(probe.Assessments);

            await probe.ProbeAsync(url, ct: timeout.Token);
            Assert.False(probe.Success);
            Assert.Equal(503, probe.StatusCode);
            Assert.Empty(probe.ImportantHeaders);
            Assert.Empty(probe.Assessments);
            Assert.Equal(new[] { "HEAD", "HEAD" }, await server);
        } finally {
            timeout.Cancel();
            listener.Stop();
        }
    }

    [Theory]
    [InlineData("405 Method Not Allowed")]
    [InlineData("501 Not Implemented")]
    public async Task UnsupportedHeadUsesGetHeadersWithoutWaitingForBody(string headStatus) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var releaseGet = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<string[]> server = ServeAsync(listener, timeout.Token,
            (headStatus, string.Empty, 0, null, TimeSpan.Zero),
            ("200 OK", "X-Content-Type-Options: nosniff\r\n", 1000000, releaseGet.Task, TimeSpan.Zero));
        string url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var probe = new UptimeProbeAnalysis();

        try {
            await probe.ProbeAsync(url, ct: timeout.Token);
            Assert.True(probe.Success);
            Assert.Equal(200, probe.StatusCode);
            Assert.Equal("nosniff", probe.ImportantHeaders["x-content-type-options"]);
            releaseGet.TrySetResult(true);
            Assert.Equal(new[] { "HEAD", "GET" }, await server);
        } finally {
            releaseGet.TrySetResult(true);
            timeout.Cancel();
            listener.Stop();
        }
    }

    [Fact]
    public async Task FallbackTtfbMeasuresGetRatherThanRejectedHead() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<string[]> server = ServeAsync(listener, timeout.Token,
            ("405 Method Not Allowed", string.Empty, 0, null, TimeSpan.FromMilliseconds(700)),
            ("200 OK", string.Empty, 0, null, TimeSpan.Zero));
        string url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var probe = new UptimeProbeAnalysis();

        try {
            await probe.ProbeAsync(url, ct: timeout.Token);
            Assert.True(probe.Success);
            Assert.True(probe.TotalMilliseconds - probe.TtfbMilliseconds >= 500,
                $"HEAD latency was included in GET TTFB: total={probe.TotalMilliseconds}, TTFB={probe.TtfbMilliseconds}");
            Assert.Equal(new[] { "HEAD", "GET" }, await server);
        } finally {
            timeout.Cancel();
            listener.Stop();
        }
    }

    [Fact]
    public async Task CallerCancellationPropagatesInsteadOfReportingTheSiteDown() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task server = CancelAfterRequestAsync(listener, timeout);
        string url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var probe = new UptimeProbeAnalysis();

        try {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe.ProbeAsync(url, ct: timeout.Token));
            await server;
        } finally {
            timeout.Cancel();
            listener.Stop();
        }
    }

    private static async Task CancelAfterRequestAsync(TcpListener listener, CancellationTokenSource timeout) {
        try {
#if NET8_0_OR_GREATER
            using TcpClient client = await listener.AcceptTcpClientAsync(timeout.Token);
#else
            using TcpClient client = await listener.AcceptTcpClientAsync();
#endif
            using NetworkStream stream = client.GetStream();
            byte[] request = new byte[2048];
            int read = await stream.ReadAsync(request, 0, request.Length, timeout.Token);
            Assert.True(read > 0);
            timeout.Cancel();
        } finally {
            listener.Stop();
        }
    }

    private static async Task<string[]> ServeAsync(TcpListener listener, CancellationToken token,
        params (string Status, string Headers, int ContentLength, Task? KeepOpen, TimeSpan DelayBeforeHeaders)[] responses) {
        var methods = new List<string>();
        try {
            foreach ((string status, string headers, int contentLength, Task? keepOpen, TimeSpan delayBeforeHeaders) in responses) {
#if NET8_0_OR_GREATER
                using TcpClient client = await listener.AcceptTcpClientAsync(token);
#else
                using TcpClient client = await listener.AcceptTcpClientAsync();
#endif
                using NetworkStream stream = client.GetStream();
                byte[] request = new byte[2048];
                int read = await stream.ReadAsync(request, 0, request.Length, token);
                Assert.True(read > 0);
                string requestLine = Encoding.ASCII.GetString(request, 0, read);
                methods.Add(requestLine.Split(' ')[0]);
                if (delayBeforeHeaders > TimeSpan.Zero) await Task.Delay(delayBeforeHeaders, token);
                byte[] response = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status}\r\n{headers}Content-Length: {contentLength}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(response, 0, response.Length, token);
                if (keepOpen != null) await keepOpen;
            }
        } catch (OperationCanceledException) when (token.IsCancellationRequested) {
            // Expected if an assertion stops the test before its next request.
        } catch (SocketException) when (token.IsCancellationRequested) {
            // .NET Framework has no cancellable accept; stopping the listener ends it.
        } finally {
            listener.Stop();
        }
        return methods.ToArray();
    }
}
