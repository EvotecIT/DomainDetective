using Xunit;

namespace DomainDetective.Tests
{
    public class TestSmtpAuthRecommendations
    {
        [Fact]
        public async Task EmitsPositiveRecommendations()
        {
            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () =>
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true, NewLine = "\r\n" };
                await writer.WriteLineAsync("220 local ESMTP");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("250-localhost");
                await writer.WriteLineAsync("250-8BITMIME");
                await writer.WriteLineAsync("250-STARTTLS");
                await writer.WriteLineAsync("250-AUTH LOGIN SCRAM-SHA-256");
                await writer.WriteLineAsync("250 OK");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("221 bye");
            });

            try
            {
                var analysis = new SmtpAuthAnalysis();
                await analysis.AnalyzeServer("localhost", port, new InternalLogger());
                var positives = RecommendationEngine.FromPositives(analysis.Assessments);
                Assert.Contains(positives, p => p.Code == SmtpAuthCodes.TlsRequired);
                Assert.Contains(positives, p => p.Code == SmtpAuthCodes.StrongMechanism);
            }
            finally
            {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
