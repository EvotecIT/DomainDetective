namespace DomainDetective.Tests {
    public class TestWhoisAnalysis {
        [Fact]
        public async Task UnsupportedTldThrows() {
            var whois = new WhoisAnalysis();
            await Assert.ThrowsAsync<UnsupportedTldException>(async () => await whois.QueryWhoisServer("example.unknown"));
        }

        [Fact]
        public async Task QueryFromLocalWhoisServerReadsLargeResponse() {
            var responseBuilder = new System.Text.StringBuilder();
            responseBuilder.AppendLine("Domain Name: example.local");
            for (int i = 0; i < 2000; i++) {
                responseBuilder.AppendLine($"Entry {i}");
            }
            var response = responseBuilder.ToString();

            using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 43);
            listener.Start();
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            var whois = new WhoisAnalysis();
            var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
            Assert.NotNull(servers);
            servers!["local"] = "localhost";

            await whois.QueryWhoisServer("example.local");

            listener.Stop();
            await serverTask;

            Assert.Equal("example.local", whois.DomainName);
            Assert.Equal(response, whois.WhoisData);
        }
    }
}
