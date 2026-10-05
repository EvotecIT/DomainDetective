using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Monitoring;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestUptimeMonitorContracts {
    [Fact]
    public async Task RepeatedProbesKeepTheSharedHttpClientUsable() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task server = ServeRequestsAsync(listener, 2);
        var url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try {
            var first = new UptimeProbeAnalysis();
            await first.ProbeAsync(url, ct: timeout.Token);
            var second = new UptimeProbeAnalysis();
            await second.ProbeAsync(url, ct: timeout.Token);

            Assert.True(first.Success);
            Assert.True(second.Success);
            await server;
        } finally {
            listener.Stop();
        }
    }

    [Theory]
    [InlineData(int.MaxValue, 0, "Up")]
    [InlineData(int.MaxValue, 2100, "Up")]
    [InlineData(0, 0, "Slow")]
    public async Task OnAnyAloneReceivesConfiguredSuccessResult(int slowThreshold, int responseDelayMs, string expectedSeverity) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task server = ServeRequestsAsync(listener, 1, responseDelayMs: responseDelayMs);
        var url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var monitor = new UptimeMonitor(new[] { url }, TimeSpan.FromHours(1)) {
            SlowTtfbMsThreshold = slowThreshold,
            OnAny = (_, severity, _) => {
                observed.TrySetResult(severity);
                return Task.CompletedTask;
            }
        };

        try {
            monitor.Start();
            Task completed = await Task.WhenAny(observed.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(observed.Task, completed);
            Assert.Equal(expectedSeverity, await observed.Task);
            await server;
        } finally {
            monitor.Stop();
            listener.Stop();
        }
    }

    [Fact]
    public async Task NotifierFailureDoesNotSuppressOnAnyDownResult() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task server = ServeRequestsAsync(listener, 1, statusCode: 503);
        var url = $"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/";
        var observed = new TaskCompletionSource<string>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var monitor = new UptimeMonitor(new[] { url }, TimeSpan.FromHours(1)) {
            Notifier = new ThrowingNotifier(),
            OnAny = (_, severity, _) => {
                observed.TrySetResult(severity);
                return Task.CompletedTask;
            }
        };

        try {
            monitor.Start();
            Task completed = await Task.WhenAny(observed.Task, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(observed.Task, completed);
            Assert.Equal("Down", await observed.Task);
            await server;
        } finally {
            monitor.Stop();
            listener.Stop();
        }
    }

    private static async Task ServeRequestsAsync(TcpListener listener, int count, int statusCode = 200, int responseDelayMs = 0) {
        string reason = statusCode == 200 ? "OK" : "Service Unavailable";
        byte[] response = Encoding.ASCII.GetBytes($"HTTP/1.1 {statusCode} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        for (int index = 0; index < count; index++) {
            using TcpClient client = await listener.AcceptTcpClientAsync();
            using NetworkStream stream = client.GetStream();
            byte[] request = new byte[1024];
            int read = await stream.ReadAsync(request, 0, request.Length);
            Assert.True(read > 0);
            if (responseDelayMs > 0) {
                await Task.Delay(responseDelayMs);
            }
            await stream.WriteAsync(response, 0, response.Length);
        }
    }

    private sealed class ThrowingNotifier : INotificationSender {
        public Task SendAsync(string message, CancellationToken ct = default) =>
            Task.FromException(new InvalidOperationException("Notification delivery failed."));
    }
}
