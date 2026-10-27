using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Xunit;

namespace DomainDetective.Tests;

public sealed class TestCertificateProfileCancellation {
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CallerCancellationDuringTlsAuthenticationKeepsTheTaskCanceled(bool profileRoute) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var caller = new CancellationTokenSource();
        var clientHello = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task peer = Task.Run(async () => {
            using TcpClient client = await listener.AcceptTcpClientAsync().WaitWithCancellation(guard.Token);
            using NetworkStream stream = client.GetStream();
            Assert.True(await stream.ReadAsync(new byte[4096], 0, 4096, guard.Token) > 0);
            clientHello.TrySetResult(true);
            await release.Task.WaitWithCancellation(guard.Token);
        });
        try {
            Task<TlsProbe.Result> probe = profileRoute
                ? CertificateProfileProbe.ProbeAsync("127.0.0.1", new CertificateProbeProfile { Id = "direct", Port = port }, TimeSpan.FromSeconds(10), caller.Token)
                : TlsProbe.ProbeWithFailureEvidenceAsync(IPAddress.Loopback, "localhost", port, TimeSpan.FromSeconds(10), caller.Token);
            await clientHello.Task.WaitWithCancellation(guard.Token);
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => probe);
            Assert.True(probe.IsCanceled);
        } finally {
            release.TrySetResult(true);
            listener.Stop();
            await peer;
        }
    }
}
