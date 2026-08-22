using System.Net;
using System.Net.Sockets;

namespace DomainDetective.Tests;

public class TestConstrainedOutboundConnections {
    [Fact]
    public async Task CertificateConnectorUsesApprovedAddressWithoutResolvingHostAgain() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var analysis = new CertificateAnalysis {
                OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback })
            };

            var connect = analysis.ConnectDirectAsync("intentionally-unresolvable.invalid", port, CancellationToken.None);
            using var accepted = await listener.AcceptTcpClientAsync();
            using var client = await connect;

            Assert.True(client.Connected);
        } finally {
            listener.Stop();
        }
    }

    [Fact]
    public async Task MailConnectorUsesApprovedAddressWithoutResolvingHostAgain() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var analysis = new MailTlsAnalysis {
                OutboundAddressResolver = (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Loopback })
            };

            var connect = analysis.ConnectAsync("intentionally-unresolvable.invalid", port, CancellationToken.None);
            using var accepted = await listener.AcceptTcpClientAsync();
            using var client = await connect;

            Assert.True(client.Connected);
        } finally {
            listener.Stop();
        }
    }

    [Fact]
    public async Task MailConnectorFiltersApprovedAddressesByRequestedFamily() {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var endpoint = new MailTransportEndpoint("intentionally-unresolvable.invalid", port) {
                AddressFamily = MailTransportAddressFamily.IPv4
            };

            var connect = MailTransportConnector.ConnectAsync(
                endpoint,
                (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.IPv6Loopback, IPAddress.Loopback }),
                CancellationToken.None);
            using var accepted = await listener.AcceptTcpClientAsync();
            using var client = await connect;

            Assert.True(client.Connected);
            var remote = Assert.IsType<IPEndPoint>(client.Client.RemoteEndPoint);
            Assert.Equal(System.Net.Sockets.AddressFamily.InterNetwork, remote.AddressFamily);
        } finally {
            listener.Stop();
        }
    }

    [Fact]
    public async Task MailConnectorRejectsPinnedAddressFromWrongFamily() {
        var endpoint = new MailTransportEndpoint("mail.example.com", 25) {
            ConnectAddress = IPAddress.IPv6Loopback,
            AddressFamily = MailTransportAddressFamily.IPv4
        };

        var exception = await Assert.ThrowsAsync<ArgumentException>(() =>
            MailTransportConnector.ConnectAsync(endpoint, null, CancellationToken.None));

        Assert.Contains("does not match", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MailConnectorRejectsPinnedAddressOutsideApprovedSet() {
        var endpoint = new MailTransportEndpoint("mail.example.com", 25) {
            ConnectAddress = IPAddress.Loopback
        };

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            MailTransportConnector.ConnectAsync(
                endpoint,
                (_, _) => Task.FromResult<IReadOnlyList<IPAddress>>(new[] { IPAddress.Parse("192.0.2.10") }),
                CancellationToken.None));

        Assert.Contains("was not approved", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task AwaitConnectDisposesSocketWhenCanceled() {
        using var client = new TcpClient();
        var socket = client.Client;
        var pendingConnect = new TaskCompletionSource<object?>();
        using var cancellation = new CancellationTokenSource();

        var connect = MailTransportConnector.AwaitConnectAsync(client, pendingConnect.Task, cancellation.Token);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connect);
        Assert.Throws<ObjectDisposedException>(() => socket.Poll(0, SelectMode.SelectRead));
    }
}
