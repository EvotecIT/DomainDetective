using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestMailLatencyRecommendations {
        [Fact]
        public async Task EmitsPositiveRecommendations() {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 test ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });
            var host = IPAddress.Loopback.ToString();
            try {
                var analysis = new MailLatencyAnalysis();
                await analysis.AnalyzeServer(host, port, new InternalLogger());
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == MailLatencyCodes.ConnectUnderThreshold);
                Assert.Contains(positives, p => p.Code == MailLatencyCodes.BannerUnderThreshold);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
