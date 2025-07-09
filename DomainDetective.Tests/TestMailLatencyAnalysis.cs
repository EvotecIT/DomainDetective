using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestMailLatencyAnalysis {
        [Fact]
        public async Task RecordsBannerLatency() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await Task.Delay(200);
                await writer.WriteLineAsync("220 slow ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try {
                var analysis = new MailLatencyAnalysis { Timeout = TimeSpan.FromSeconds(5) };
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var result = analysis.ServerResults[$"localhost:{port}"];
                Assert.True(result.BannerSuccess);
                Assert.True(result.BannerTime >= TimeSpan.FromMilliseconds(200));
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task RecordsConnectTimeout() {
            var analysis = new MailLatencyAnalysis { Timeout = TimeSpan.FromMilliseconds(300) };
            await analysis.AnalyzeServer("203.0.113.1", 25, new InternalLogger());
            var result = analysis.ServerResults["203.0.113.1:25"];
            Assert.False(result.ConnectSuccess);
        }
    }
}
