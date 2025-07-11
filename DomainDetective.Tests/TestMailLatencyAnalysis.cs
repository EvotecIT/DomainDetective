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
                client.NoDelay = true;
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await Task.Delay(200);
                await writer.WriteLineAsync("220 slow ESMTP");
                await writer.FlushAsync();
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
                await writer.FlushAsync();
            });

            try {
                var analysis = new MailLatencyAnalysis { Timeout = TimeSpan.FromSeconds(5) };
                var host = IPAddress.Loopback.ToString();
                await analysis.AnalyzeServer(host, port, new InternalLogger());
                var result = analysis.ServerResults[$"{host}:{port}"];
                Assert.True(result.BannerSuccess, $"Connect:{result.ConnectSuccess} Banner:{result.BannerSuccess} ConnectTime:{result.ConnectTime.TotalMilliseconds} BannerTime:{result.BannerTime.TotalMilliseconds}");
                Assert.True(result.BannerTime >= TimeSpan.FromMilliseconds(150), $"BannerTime {result.BannerTime.TotalMilliseconds}ms was shorter than expected");
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
