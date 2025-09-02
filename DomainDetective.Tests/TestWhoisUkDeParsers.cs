using System.Threading.Tasks;

namespace DomainDetective.Tests;

public class TestWhoisUkDeParsers {
    [Fact]
    public async Task ParsesNominetUkFormat_ForOrgUk() {
        var response = string.Join("\n", new[] {
            "Domain name:",
            "    example.org.uk",
            "",
            "Registrar:",
            "    Foo Registrar",
            "    URL: https://foo.example",
            "",
            "Relevant dates:",
            "    Registered on: 01-Jan-2020",
            "    Expiry date: 01-Jan-2026",
            "    Last updated: 01-Dec-2024",
            "",
            "Name servers:",
            "    ns1.example.net",
            "    ns2.example.net",
        });

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
            var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var lockObj = lockField?.GetValue(whois);
            lock (lockObj!) {
                servers!["uk"] = $"localhost:{port}";
            }

            await whois.QueryWhoisServer("example.org.uk");
            Assert.Equal("example.org.uk", whois.DomainName);
            Assert.Equal("Foo Registrar", whois.Registrar);
            Assert.Contains("ns1.example.net", whois.NameServers);
            Assert.NotNull(whois.ExpiryDate);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }

    [Fact]
    public async Task ParsesDenicDeFormat() {
        var response = string.Join("\n", new[] {
            "Domain:    EXAMPLE.DE",
            "Changed:   2024-06-01T12:34:56+02:00",
            "Nserver:   ns1.example.de",
            "Nserver:   ns2.example.de",
        });

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
            var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            var lockObj = lockField?.GetValue(whois);
            lock (lockObj!) {
                servers!["de"] = $"localhost:{port}";
            }

            await whois.QueryWhoisServer("example.de");
            Assert.Contains("ns1.example.de", whois.NameServers);
            Assert.Equal("2024-06-01T12:34:56+02:00", whois.LastUpdated);
        } finally {
            listener.Stop();
            await serverTask;
        }
    }
}

