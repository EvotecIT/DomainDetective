using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Threading;

namespace DomainDetective {
    public class STARTTLSAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            bool supports = await CheckStartTls(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = supports;
        }

        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                await AnalyzeServer(host, port, logger, cancellationToken);
            }
        }

        private static async Task<bool> CheckStartTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            using var client = new TcpClient();
            try {
                await client.ConnectAsync(host, port);
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

                await reader.ReadLineAsync();
                cancellationToken.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"EHLO example.com");

                var capabilities = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
                string line;
                while ((line = await reader.ReadLineAsync()) != null) {
                    cancellationToken.ThrowIfCancellationRequested();
                    logger?.WriteVerbose($"EHLO response: {line}");
                    if (line.StartsWith("250")) {
                        string capabilityLine = line.Substring(4).Trim();
                        foreach (var part in capabilityLine.Split(new[] { ' ' }, System.StringSplitOptions.RemoveEmptyEntries)) {
                            capabilities.Add(part);
                        }
                        if (!line.StartsWith("250-")) {
                            break;
                        }
                    } else if (line.StartsWith("5") || line.StartsWith("4")) {
                        break;
                    }
                }

                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
                try {
                    await reader.ReadLineAsync();
                } catch (IOException) {
                    // swallow disconnect after QUIT
                }

                return capabilities.Contains("STARTTLS");
            } catch (System.Exception ex) {
                logger?.WriteError("STARTTLS check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            }
        }
    }
}