using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestPortAvailabilityAnalysis {
        [Fact]
        public async Task ReportsSuccessAndLatency() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var acceptTask = listener.AcceptTcpClientAsync();

            try {
                var analysis = new PortAvailabilityAnalysis();
                await analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger());
                var result = analysis.ServerResults[$"127.0.0.1:{port}"];
                Assert.True(result.Success);
                Assert.True(result.Latency > TimeSpan.Zero);
                using var c = await acceptTask; // ensure the connection was accepted
            } finally {
                listener.Stop();
            }
        }

        [Fact]
        public async Task ReportsFailureWhenPortClosed() {
            var port = GetFreePort();
            var analysis = new PortAvailabilityAnalysis { Timeout = TimeSpan.FromMilliseconds(200) };
            await analysis.AnalyzeServer("127.0.0.1", port, new InternalLogger());
            var result = analysis.ServerResults[$"127.0.0.1:{port}"];
            Assert.False(result.Success);
        }

        [Fact]
        public async Task ResultsDoNotAccumulateAcrossCalls() {
            var listener1 = new TcpListener(IPAddress.Loopback, 0);
            listener1.Start();
            var port1 = ((IPEndPoint)listener1.LocalEndpoint).Port;
            var acceptTask1 = listener1.AcceptTcpClientAsync();

            var analysis = new PortAvailabilityAnalysis();
            try {
                await analysis.AnalyzeServer("127.0.0.1", port1, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                using var c1 = await acceptTask1; // ensure the connection was accepted before stopping
            } finally {
                listener1.Stop();
            }

            var listener2 = new TcpListener(IPAddress.Loopback, 0);
            listener2.Start();
            var port2 = ((IPEndPoint)listener2.LocalEndpoint).Port;
            var acceptTask2 = listener2.AcceptTcpClientAsync();

            try {
                await analysis.AnalyzeServer("127.0.0.1", port2, new InternalLogger());
                Assert.Single(analysis.ServerResults);
                Assert.False(analysis.ServerResults.ContainsKey($"127.0.0.1:{port1}"));
                Assert.True(analysis.ServerResults.ContainsKey($"127.0.0.1:{port2}"));
                using var c2 = await acceptTask2; // wait for listener to accept before stopping
            } finally {
                listener2.Stop();
            }
        }

        private static int GetFreePort() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }
    }
}
