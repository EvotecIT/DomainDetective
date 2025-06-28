using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Checks whether SMTP servers advertise the STARTTLS capability.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class STARTTLSAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tests a single server for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            bool supports = await CheckStartTls(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = supports;
        }

        /// <summary>
        /// Tests multiple servers for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                foreach (var port in ports) {
                    cancellationToken.ThrowIfCancellationRequested();
                    bool supports = await CheckStartTls(host, port, logger, cancellationToken);
                    ServerResults[$"{host}:{port}"] = supports;
                }
            }
        }

        /// <summary>
        /// Performs the low-level STARTTLS negotiation.
        /// </summary>
        private async Task<bool> CheckStartTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(host, port, timeoutCts.Token);
#else
                await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
#endif
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

#if NET8_0_OR_GREATER
                await reader.ReadLineAsync(timeoutCts.Token);
#else
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"EHLO example.com");

                var capabilities = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
                string line;
                while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                    timeoutCts.Token.ThrowIfCancellationRequested();
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
                    await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                } catch (IOException) {
                    // swallow disconnect after QUIT
                }

                return capabilities.Contains("STARTTLS");
            } catch (System.Exception ex) {
                logger?.WriteError("STARTTLS check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            } finally {
                client.Dispose();
            }
        }
    }
}