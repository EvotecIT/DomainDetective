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
}
