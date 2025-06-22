using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective {
    public class STARTTLSAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger) {
            bool supports = await CheckStartTls(host, port, logger);
            ServerResults[$"{host}:{port}"] = supports;
        }

        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger) {
            foreach (var host in hosts) {
                await AnalyzeServer(host, port, logger);
            }
        }

        private static async Task<bool> CheckStartTls(string host, int port, InternalLogger logger) {
            using var client = new TcpClient();
            try {
                await client.ConnectAsync(host, port);
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

                await reader.ReadLineAsync();
                await writer.WriteLineAsync($"EHLO example.com");

                var capabilities = new List<string>();
                string line;
                while ((line = await reader.ReadLineAsync()) != null) {
                    logger?.WriteVerbose($"EHLO response: {line}");
                    if (line.StartsWith("250")) {
                        string capability = line.Substring(4).Trim();
                        capabilities.Add(capability);
                        if (!line.StartsWith("250-")) {
                            break;
                        }
                    } else if (line.StartsWith("5") || line.StartsWith("4")) {
                        break;
                    }
                }

                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
                await reader.ReadLineAsync();

                return capabilities.Exists(c => c.Equals("STARTTLS", System.StringComparison.OrdinalIgnoreCase));
            } catch (System.Exception ex) {
                logger?.WriteError("STARTTLS check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            }
        }
    }
}