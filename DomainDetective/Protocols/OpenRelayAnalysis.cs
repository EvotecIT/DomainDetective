using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs open relay checks against SMTP servers.
    /// </summary>
    public class OpenRelayAnalysis {
        public Dictionary<string, OpenRelayStatus> ServerResults { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tests a single server for open relay capabilities.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new TcpClient();
            var status = await TryRelay(client, host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = status;
        }

        /// <summary>
        /// Tests multiple servers for open relay capabilities.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                foreach (var port in ports) {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var client = new TcpClient();
                    var status = await TryRelay(client, host, port, logger, cancellationToken);
                    ServerResults[$"{host}:{port}"] = status;
                }
            }
        }

        /// <summary>
        /// Attempts to send a relay through the specified server.
        /// </summary>
        private async Task<OpenRelayStatus> TryRelay(TcpClient client, string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
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

                await ReadResponseAsync(reader, timeoutCts.Token);
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"HELO example.com");
                await ReadResponseAsync(reader, timeoutCts.Token);
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("MAIL FROM:<test@example.com>");
                var mailResp = await ReadResponseAsync(reader, timeoutCts.Token);
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("RCPT TO:<test@example.org>");
                var rcptResp = await ReadResponseAsync(reader, timeoutCts.Token);
#if NET8_0_OR_GREATER
                await writer.WriteLineAsync("QUIT".AsMemory(), timeoutCts.Token);
                await writer.FlushAsync(timeoutCts.Token);
#else
                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
#endif
                await ReadResponseAsync(reader, timeoutCts.Token);

                logger?.WriteVerbose($"MAIL FROM response: {mailResp}");
                logger?.WriteVerbose($"RCPT TO response: {rcptResp}");

                return mailResp != null && mailResp.StartsWith("250") && rcptResp != null && rcptResp.StartsWith("250")
                    ? OpenRelayStatus.AllowsRelay
                    : OpenRelayStatus.Denied;
            } catch (TaskCanceledException ex) {
                throw new OperationCanceledException(ex.Message, ex, cancellationToken);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteError("Open relay check failed for {0}:{1} - {2}", host, port, ex.Message);
                return OpenRelayStatus.ConnectionFailed;
            }
        }

        /// <summary>
        /// Reads a line from the SMTP server until the final response is received.
        /// </summary>
        private static async Task<string?> ReadResponseAsync(StreamReader reader, CancellationToken token) {
#if NET8_0_OR_GREATER
            string? line = await reader.ReadLineAsync(token);
#else
            string? line = await reader.ReadLineAsync().WaitWithCancellation(token);
#endif
            if (line == null) {
                return null;
            }

            string? current = line;
            while (current.StartsWith("250-") || current.StartsWith("220-")) {
#if NET8_0_OR_GREATER
                current = await reader.ReadLineAsync(token);
#else
                current = await reader.ReadLineAsync().WaitWithCancellation(token);
#endif
                if (current == null) {
                    break;
                }
            }

            return current;
        }
    }
}