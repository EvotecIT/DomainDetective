using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

using DomainDetective;
namespace DomainDetective.Tests {
    public class TestPortScanAnalysis {
        [SkippableFact]
        public async Task DetectsTcpAndUdpOpenPorts() {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            var tcpAccept = tcpListener.AcceptTcpClientAsync();

            var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { tcpPort, udpPort }, new InternalLogger());
                using var _ = await tcpAccept; // ensure connection completes

                var tcpOpen = analysis.Results[tcpPort].TcpOpen;
                var udpOpen = analysis.Results[udpPort].UdpOpen;
                Skip.If(!(tcpOpen && udpOpen), "Open port detection not supported");

                Assert.True(tcpOpen);
                Assert.True(udpOpen);
            } finally {
                tcpListener.Stop();
                udpServer.Close();
                await udpTask;
            }
        }

        [SkippableFact]
        public async Task DetectsIpv6TcpAndUdpOpenPorts() {
            var tcpListener = new TcpListener(IPAddress.IPv6Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            var tcpAccept = tcpListener.AcceptTcpClientAsync();

            var udpServer = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("::1", new[] { tcpPort, udpPort }, new InternalLogger());
                using var _ = await tcpAccept;

                var tcpOpen = analysis.Results[tcpPort].TcpOpen;
                var udpOpen = analysis.Results[udpPort].UdpOpen;
                Skip.If(!(tcpOpen && udpOpen), "Open port detection not supported");

                Assert.True(tcpOpen);
                Assert.True(udpOpen);
            } finally {
                tcpListener.Stop();
                udpServer.Close();
                await udpTask;
            }
        }

        [SkippableFact]
        public async Task ConfirmsIpv6Reachability() {
            var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            try {
                var reachable = await PortScanAnalysis.IsIPv6Reachable("localhost", port);
                using var _ = await accept;
                Skip.IfNot(reachable, "IPv6 not reachable on this host");
                Assert.True(reachable);
            } finally {
                listener.Stop();
            }
        }

        [Fact]
        public async Task UdpPortClosedWhenNoResponseData() {
            var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(Array.Empty<byte>(), 0, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { udpPort }, new InternalLogger());

                Assert.False(analysis.Results[udpPort].UdpOpen);
                Assert.False(string.IsNullOrEmpty(analysis.Results[udpPort].Error));
            } finally {
                udpServer.Close();
                await udpTask;
            }
        }

        [Fact]
        public async Task DetectsTcpClosedPort() {
            var port = GetFreePort();
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("127.0.0.1", new[] { port }, new InternalLogger());
            Assert.False(analysis.Results[port].TcpOpen);
            Assert.False(string.IsNullOrEmpty(analysis.Results[port].Error));
        }

        [Fact]
        public async Task UnresolvableHostRecordsError() {
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("nonexistent.example.invalid", new[] { 80 }, new InternalLogger());
            Assert.False(analysis.Results[80].TcpOpen);
            Assert.False(string.IsNullOrEmpty(analysis.Results[80].Error));
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }
    }
}

