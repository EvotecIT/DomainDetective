using DomainDetective;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Xunit;

namespace DomainDetective.Tests {
    public class TestWhoisSnapshots {

        [Fact]
        public async Task DetectsSnapshotChanges() {
            var first = string.Join("\n", new[] {
                "Domain Name: snapshot.local",
                "Registry Expiry Date: 2024-01-01"
            });
            var second = string.Join("\n", new[] {
                "Domain Name: snapshot.local",
                "Registry Expiry Date: 2025-01-01"
            });
            var dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(dir);

            var listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(first);
            });
            try {
                var whois = new WhoisAnalysis { SnapshotDirectory = dir };
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["local"] = $"localhost:{port}";
                }
                await whois.QueryWhoisServer("snapshot.local");
                whois.SaveSnapshot();
            } finally {
                listener.Stop();
                await serverTask;
            }

            listener = new TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            serverTask = Task.Run(async () => {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                using var reader = new StreamReader(stream);
                await reader.ReadLineAsync();
                using var writer = new StreamWriter(stream) { AutoFlush = true };
                await writer.WriteAsync(second);
            });
            List<string> diff;
            try {
                var whois = new WhoisAnalysis { SnapshotDirectory = dir };
                var field = typeof(WhoisAnalysis).GetField("WhoisServers", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var servers = (Dictionary<string, string>?)field?.GetValue(whois);
                Assert.NotNull(servers);
                var lockField = typeof(WhoisAnalysis).GetField("_whoisServersLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
                var lockObj = lockField?.GetValue(whois);
                Assert.NotNull(lockObj);
                lock (lockObj!) {
                    servers!["local"] = $"localhost:{port}";
                }
                await whois.QueryWhoisServer("snapshot.local");
                diff = whois.GetWhoisChanges().ToList();
                whois.SaveSnapshot();
            } finally {
                listener.Stop();
                await serverTask;
            }

            Assert.Contains("+ Registry Expiry Date: 2025-01-01", diff);
            Assert.Contains("- Registry Expiry Date: 2024-01-01", diff);
        }
    }
}
