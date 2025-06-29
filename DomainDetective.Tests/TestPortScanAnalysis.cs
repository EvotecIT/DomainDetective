using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

using DomainDetective;
namespace DomainDetective.Tests {
    public class TestPortScanAnalysis {
        [Fact]
        public async Task DetectsTcpAndUdpOpenPorts() {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            var tcpAccept = tcpListener.AcceptTcpClientAsync();

            var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(r.Buffer, r.Buffer.Length, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("localhost", new[] { tcpPort, udpPort }, new InternalLogger());
                using var _ = await tcpAccept; // ensure connection completes

                Assert.True(analysis.Results[tcpPort].TcpOpen);
                Assert.True(analysis.Results[udpPort].UdpOpen);
            } finally {
                tcpListener.Stop();
                udpServer.Close();
                await udpTask;
            }
        }

        [Fact]
        public async Task ConfirmsIpv6Reachability() {
            var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            try {
                var reachable = await PortScanAnalysis.IsIPv6Reachable("localhost", port);
                using var _ = await accept;
                Assert.True(reachable);
            } finally {
                listener.Stop();
            }
        }
    }
}

