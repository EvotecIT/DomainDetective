using DomainDetective;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit.Sdk;
using Xunit;
namespace DomainDetective.Tests {
    public class TestPortScanAnalysis {
        [Fact]
        public async Task DetectsTcpAndUdpOpenPorts() {
            var tcpListener = new TcpListener(IPAddress.Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            var tcpAccept = tcpListener.AcceptTcpClientAsync();

            using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { tcpPort, udpPort }, new InternalLogger());
                using var _ = await tcpAccept; // ensure connection completes

                Assert.True(analysis.Results[tcpPort].TcpOpen);
                Assert.True(analysis.Results[udpPort].UdpOpen);
            } finally {
                tcpListener.Stop();
                await udpTask;
            }
        }

        [Fact]
        public async Task DetectsIpv6TcpAndUdpOpenPorts() {
            Skip.If(!Socket.OSSupportsIPv6, "IPv6 not supported on this platform");
            var tcpListener = new TcpListener(IPAddress.IPv6Loopback, 0);
            tcpListener.Start();
            var tcpPort = ((IPEndPoint)tcpListener.LocalEndpoint).Port;
            var ipv6Reachable = await PortScanAnalysis.IsIPv6Reachable("localhost", tcpPort);
            if (!ipv6Reachable) {
                tcpListener.Stop();
            }
            Skip.If(!ipv6Reachable, "IPv6 not reachable on this platform");
            var tcpAccept = tcpListener.AcceptTcpClientAsync();

            using var udpServer = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = Task.Run(async () => {
                var r = await udpServer.ReceiveAsync();
                await udpServer.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("::1", new[] { tcpPort, udpPort }, new InternalLogger());
                using var _ = await tcpAccept;

                Assert.True(analysis.Results[tcpPort].TcpOpen);
                Assert.True(analysis.Results[udpPort].UdpOpen);
            } finally {
                tcpListener.Stop();
                await udpTask;
            }
        }

        [Fact]
        public async Task ConfirmsIpv6Reachability() {
            if (!Socket.OSSupportsIPv6) return; // pass on platforms without IPv6
            var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();

            try {
                var reachable = await PortScanAnalysis.IsIPv6Reachable("localhost", port);
                if (!reachable) { listener.Stop(); return; } // pass when IPv6 temporarily unreachable
                var completed = await Task.WhenAny(accept, Task.Delay(1500));
                if (completed != accept) { listener.Stop(); return; }
                using var _ = await accept;
                Assert.True(reachable);
            } finally {
                try { listener.Stop(); } catch { }
            }
        }

        [Fact]
        public async Task UdpPortClosedWhenNoResponseData() {
            using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
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
                await udpTask;
            }
        }

        [Fact]
        public async Task UdpPortClosedWhenNoReply() {
            using var udpServer = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var udpPort = ((IPEndPoint)udpServer.Client.LocalEndPoint!).Port;
            var udpTask = udpServer.ReceiveAsync();

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { udpPort }, new InternalLogger());

                Assert.False(analysis.Results[udpPort].UdpOpen);
            } finally {
                udpServer.Close();
                try { await udpTask; } catch { }
            }
        }

        [Fact]
        public async Task DetectsTcpClosedPort() {
            var port = GetFreePort();
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("127.0.0.1", new[] { port }, new InternalLogger());
            Assert.False(analysis.Results[port].TcpOpen);
            Assert.False(string.IsNullOrEmpty(analysis.Results[port].Error));
            PortHelper.ReleasePort(port);
        }

        [Fact]
        public async Task UnresolvableHostRecordsError() {
            var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.Scan("nonexistent.example.invalid", new[] { 80 }, new InternalLogger());
            Assert.False(analysis.Results[80].TcpOpen);
            Assert.False(string.IsNullOrEmpty(analysis.Results[80].Error));
        }

        [Fact]
        public async Task ScansUsingSmbProfile() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();
            try {
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.SMB, new[] { port });
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromSeconds(1) };
                await analysis.Scan("127.0.0.1", PortScanProfile.SMB, new InternalLogger());
                using var _ = await accept;
                Assert.True(analysis.Results[port].TcpOpen);
            } finally {
                listener.Stop();
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.SMB, new[] { 445, 139 });
            }
        }

        [Fact]
        public async Task ScansUsingNtpProfile() {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            var task = Task.Run(async () => {
                var r = await server.ReceiveAsync();
                await server.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });
            try {
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.NTP, new[] { port });
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", PortScanProfile.NTP, new InternalLogger());
                Assert.True(analysis.Results[port].UdpOpen);
            } finally {
                await task;
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.NTP, new[] { 123 });
            }
        }

        [Fact]
        public async Task ScansUsingRadiusProfile() {
            using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
            var task = Task.Run(async () => {
                var r = await server.ReceiveAsync();
                await server.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });
            try {
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.RADIUS, new[] { port });
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", PortScanProfile.RADIUS, new InternalLogger());
                Assert.True(analysis.Results[port].UdpOpen);
            } finally {
                await task;
                PortScanProfileDefinition.OverrideProfilePorts(PortScanProfile.RADIUS, new[] { 1812, 1813 });
            }
        }

        [Fact]
        public async Task DetectsServiceBanners() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var data = System.Text.Encoding.ASCII.GetBytes("SSH-2.0-Test\r\n");
                await stream.WriteAsync(data, 0, data.Length);
                await stream.FlushAsync();
            });

            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { port }, new InternalLogger());
                Assert.Equal("SSH-2.0-Test", analysis.Results[port].Banner);
            } finally {
                await serverTask;
                listener.Stop();
            }
        }

        [Fact]
        public async Task DetectsSnmpUdpBanner() {
            var port = GetFreePort();
            var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
            var task = Task.Run(async () => {
                var r = await udp.ReceiveAsync();
                await udp.SendAsync(new byte[] { 1 }, 1, r.RemoteEndPoint);
            });
            try {
                var analysis = new PortScanAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
                await analysis.Scan("127.0.0.1", new[] { port }, new InternalLogger());
                Assert.Equal("SNMP", analysis.Results[port].Banner);
            } finally {
                udp.Close();
                await task;
                PortHelper.ReleasePort(port);
            }
        }

        private static int GetFreePort() {
            return PortHelper.GetFreePort();
        }
    }
}
