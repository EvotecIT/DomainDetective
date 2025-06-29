using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
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
        public Dictionary<string, bool> DowngradeDetected { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tests a single server for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            DowngradeDetected.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            (bool supports, bool downgrade) = await CheckStartTls(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = supports;
            DowngradeDetected[$"{host}:{port}"] = downgrade;
        }

        /// <summary>
        /// Tests multiple servers for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            DowngradeDetected.Clear();
            foreach (var host in hosts) {
                foreach (var port in ports) {
                    cancellationToken.ThrowIfCancellationRequested();
                    (bool supports, bool downgrade) = await CheckStartTls(host, port, logger, cancellationToken);
                    ServerResults[$"{host}:{port}"] = supports;
                    DowngradeDetected[$"{host}:{port}"] = downgrade;
                }
            }
        }

        /// <summary>
        /// Resolves the specified host and returns a <see cref="DnsEndPoint"/>
        /// with address family information when an IP address is provided.
        /// </summary>
        private static DnsEndPoint GetEndPoint(string host, int port) {
            return IPAddress.TryParse(host, out IPAddress? ip)
                ? new DnsEndPoint(host, port, ip.AddressFamily)
                : new DnsEndPoint(host, port);
        }

        /// <summary>
        /// Performs the low-level STARTTLS negotiation.
        /// </summary>
        private async Task<(bool Advertised, bool Downgrade)> CheckStartTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            var endPoint = GetEndPoint(host, port);
            var client = endPoint.AddressFamily == AddressFamily.Unspecified
                ? new TcpClient()
                : new TcpClient(endPoint.AddressFamily);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
#if NET6_0_OR_GREATER
                if (endPoint.AddressFamily == AddressFamily.Unspecified) {
                    await client.ConnectAsync(host, port, timeoutCts.Token);
                } else {
                    await client.Client.ConnectAsync(endPoint, timeoutCts.Token);
                }
#else
                if (endPoint.AddressFamily == AddressFamily.Unspecified) {
                    await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
                } else {
                    await client.Client.ConnectAsync(endPoint).WaitWithCancellation(timeoutCts.Token);
                }
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

                bool advertised = capabilities.Contains("STARTTLS");
                bool downgrade = false;

                if (!advertised) {
                    await writer.WriteLineAsync("STARTTLS");
                    var resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                    if (resp != null && resp.StartsWith("220")) {
                        try {
                            using var ssl = new System.Net.Security.SslStream(network, false, static (_, _, _, _) => true);
#if NET8_0_OR_GREATER
                            await ssl.AuthenticateAsClientAsync(host, null, System.Security.Authentication.SslProtocols.Tls13 | System.Security.Authentication.SslProtocols.Tls12, false)
                                .WaitWithCancellation(timeoutCts.Token);
#else
                            await ssl.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
#endif
                            using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                            await secureWriter.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                            downgrade = true;
                        } catch (Exception ex) {
                            logger?.WriteVerbose($"STARTTLS handshake failed for {host}:{port} - {ex.Message}");
                        }
                    }
                }

                if (advertised || !downgrade) {
                    await writer.WriteLineAsync("QUIT");
                    await writer.FlushAsync();
                    try {
                        await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                    } catch (IOException) {
                        // swallow disconnect after QUIT
                    }
                }

                return (advertised || downgrade, downgrade);
            } catch (System.Exception ex) {
                logger?.WriteError("STARTTLS check failed for {0}:{1} - {2}", host, port, ex.Message);
                return (false, false);
            } finally {
                client.Dispose();
            }
        }
    }
}