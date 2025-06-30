using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Retrieves advertised AUTH mechanisms from SMTP servers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SmtpAuthAnalysis {
        /// <summary>Supported authentication methods per server.</summary>
        public Dictionary<string, string[]> ServerMechanisms { get; } = new();
        /// <summary>Connection timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Checks a single server for AUTH capabilities.</summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerMechanisms.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            var mechs = await QueryAuth(host, port, logger, cancellationToken);
            ServerMechanisms[$"{host}:{port}"] = mechs;
        }

        /// <summary>Checks multiple servers for AUTH capabilities.</summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerMechanisms.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                var mechs = await QueryAuth(host, port, logger, cancellationToken);
                ServerMechanisms[$"{host}:{port}"] = mechs;
            }
        }

        private async Task<string[]> QueryAuth(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            using var client = new TcpClient();
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

                var mechanisms = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool hasAuth = false;
                bool has8BitMime = false;
                string? line;
                while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    logger?.WriteVerbose($"EHLO response: {line}");
                    if (line.StartsWith("250", StringComparison.Ordinal)) {
                        var cap = line.Substring(4).Trim();
                        if (cap.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase)) {
                            var authPart = cap.Substring(4).TrimStart('=', ' ');
                            foreach (var part in authPart.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
                                mechanisms.Add(part);
                            }
                            hasAuth = true;
                        } else if (string.Equals(cap, "8BITMIME", StringComparison.OrdinalIgnoreCase)) {
                            has8BitMime = true;
                        }
                        if (!line.StartsWith("250-", StringComparison.Ordinal)) {
                            break;
                        }
                    } else if (line.StartsWith("4") || line.StartsWith("5")) {
                        break;
                    }
                }

#if NET8_0_OR_GREATER
                await writer.WriteLineAsync("QUIT".AsMemory(), timeoutCts.Token);
                await writer.FlushAsync(timeoutCts.Token);
#else
                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
#endif
                try {
                    await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                } catch (IOException) {
                    // ignore
                }

                if (hasAuth && !has8BitMime) {
                    logger?.WriteWarning("SMTP server {0}:{1} advertises AUTH but not 8BITMIME.", host, port);
                }

                return mechanisms.Count == 0 ? Array.Empty<string>() : new List<string>(mechanisms).ToArray();
            } catch (Exception ex) {
                logger?.WriteError("SMTP AUTH check failed for {0}:{1} - {2}", host, port, ex.Message);
                return Array.Empty<string>();
            }
        }
    }
}
