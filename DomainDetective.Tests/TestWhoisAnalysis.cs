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

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                // Ensure thread-safe modification of the internal WHOIS servers collection
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["local"] = $"localhost:{port}";
                }

                await whois.QueryWhoisServer("example.local");

                Assert.Equal("example.local", whois.DomainName);
                var expected = response.Replace("\r\n", "\n").Replace("\r", "\n");
                var actual = whois.WhoisData.Replace("\r\n", "\n").Replace("\r", "\n");
                Assert.Equal(expected, actual);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }

        [Fact]
        public async Task QueryFromLocalWhoisServerReadsLargeResponseCaseInsensitive() {
            var responseBuilder = new System.Text.StringBuilder();
            responseBuilder.AppendLine("Domain Name: example.local");
            for (int i = 0; i < 2000; i++) {
                responseBuilder.AppendLine($"Entry {i}");
            }
            var response = responseBuilder.ToString();

            var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = System.Threading.Tasks.Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new System.IO.StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new System.IO.StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(response);
            });

            try {
                var whois = new WhoisAnalysis();
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (System.Collections.Generic.Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                servers!["local"] = $"localhost:{port}";

                await whois.QueryWhoisServer("EXAMPLE.LOCAL");

                Assert.Equal("example.local", whois.DomainName);
                var expected = response.Replace("\r\n", "\n").Replace("\r", "\n");
                var actual = whois.WhoisData.Replace("\r\n", "\n").Replace("\r", "\n");
                Assert.Equal(expected, actual);
            } finally {
                listener.Stop();
                await serverTask;
            }
        }
    }
}
