using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestMailHostnameResolution {
    [Theory]
    [InlineData(MailTransportAddressFamily.Any)]
    [InlineData(MailTransportAddressFamily.IPv4)]
    public async Task DefaultHostnameResolutionConnectsToAnApprovedLocalCandidate(MailTransportAddressFamily family) {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task<TcpClient>? accept = null;
        try {
            accept = listener.AcceptTcpClientAsync();
            using var client = await MailTransportConnector.ConnectAsync(
                new MailTransportEndpoint("localhost", ((IPEndPoint)listener.LocalEndpoint).Port) { AddressFamily = family }, null, guard.Token);
            using var peer = await accept.WaitWithCancellation(guard.Token);
            Assert.Equal(IPAddress.Loopback, ((IPEndPoint)client.Client.RemoteEndPoint!).Address);
        } finally {
            listener.Stop();
            if (accept != null) {
                try { (await accept).Dispose(); }
                catch (SocketException) { }
                catch (ObjectDisposedException) { }
            }
        }
    }

    [Fact]
    public async Task CallerCancellationStopsWaitingForHostnameResolutionBeforeAnyConnect() {
        var pending = new TaskCompletionSource<IReadOnlyList<IPAddress>>(TaskCreationOptions.RunContinuationsAsynchronously);
        var entered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        using var guard = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(guard.Token);
        var connect = MailTransportConnector.ConnectAsync(new MailTransportEndpoint("fixture.example", 25), (_, _) => {
            entered.TrySetResult(true);
            return pending.Task;
        }, canceled.Token);
        try {
            await entered.Task.WaitWithCancellation(guard.Token);
            canceled.Cancel();
            var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connect.WaitWithCancellation(guard.Token));
            Assert.Equal(canceled.Token, error.CancellationToken);
            Assert.False(guard.IsCancellationRequested);
        } finally {
            pending.TrySetException(new SocketException((int)SocketError.HostNotFound));
            try { await pending.Task; } catch (SocketException) { }
            try { (await connect).Dispose(); } catch (OperationCanceledException) { }
        }
    }
}
