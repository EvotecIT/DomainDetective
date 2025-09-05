using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using DomainDetective.Recommendations;
using Xunit;

namespace DomainDetective.Tests {
    public class TestMailLatencyRecommendations {
        [Fact]
        public void RegistersCodes() {
            var map = new Dictionary<string, RecommendationAdvice>();
            new MailLatencyRecommendations().Register(map);
            Assert.Contains(MailLatencyCodes.ConnectFast, map.Keys);
            Assert.Contains(MailLatencyCodes.BannerFast, map.Keys);
        }

        [Fact]
        public async Task EmitsPositiveAdvice() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var accept = listener.AcceptTcpClientAsync();
            var server = accept.ContinueWith(async t => {
                using var client = await t;
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                using var writer = new StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 test");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            }).Unwrap();
            try {
                var analysis = new MailLatencyAnalysis { Timeout = System.TimeSpan.FromSeconds(5) };
                var logger = new InternalLogger();
                await analysis.AnalyzeServer("127.0.0.1", port, logger);
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == MailLatencyCodes.ConnectFast);
                Assert.Contains(positives, p => p.Code == MailLatencyCodes.BannerFast);
                await server;
            } finally {
                listener.Stop();
            }
        }
    }
}
