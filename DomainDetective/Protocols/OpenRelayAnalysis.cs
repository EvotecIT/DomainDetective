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
    /// <para>Part of the DomainDetective project.</para>
    public class OpenRelayAnalysis {
        /// <summary>Result of a single open relay check.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class OpenRelayResult {
            /// <summary>Status of the relay attempt.</summary>
            public OpenRelayStatus Status { get; init; }
            /// <summary>Socket error code when <see cref="Status"/> is <see cref="OpenRelayStatus.ConnectionFailed"/>.</summary>
            public SocketError? SocketErrorCode { get; init; }
        }

        public Dictionary<string, OpenRelayResult> ServerResults { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Tests a single server for open relay capabilities.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            var result = await TryRelay(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = result;
        }

        /// <summary>
        /// Tests multiple servers for open relay capabilities.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                foreach (var port in ports) {
                    cancellationToken.ThrowIfCancellationRequested();
                    var result = await TryRelay(host, port, logger, cancellationToken);
                    ServerResults[$"{host}:{port}"] = result;
                }
            }
        }

        /// <summary>
        /// Attempts to send a relay through the specified server.
        /// </summary>
        private async Task<OpenRelayResult> TryRelay(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
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

                await ReadResponseAsync(reader, timeoutCts.Token);
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"HELO {host}");
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

                int mailCode = ParseStatusCode(mailResp);
                int rcptCode = ParseStatusCode(rcptResp);
                var status = mailCode >= 200 && mailCode < 300 && rcptCode >= 200 && rcptCode < 300 && mailCode != 550 && mailCode != 551 && rcptCode != 550 && rcptCode != 551
                    ? OpenRelayStatus.AllowsRelay
                    : OpenRelayStatus.Denied;
                return new OpenRelayResult { Status = status };
            } catch (TaskCanceledException ex) {
                throw new OperationCanceledException(ex.Message, ex, cancellationToken);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteError("Open relay check failed for {0}:{1} - {2}", host, port, ex.Message);
                SocketError? errorCode = (ex as SocketException)?.SocketErrorCode;
                return new OpenRelayResult { Status = OpenRelayStatus.ConnectionFailed, SocketErrorCode = errorCode };
            }
        }

        private static int ParseStatusCode(string? response) {
            if (response != null && response.Length >= 3 && int.TryParse(response.Substring(0, 3), out int code)) {
                return code;
            }
            return -1;
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

            string code = line.Length >= 3 ? line.Substring(0, 3) : string.Empty;
            string? lastLine = line;

            while (line.Length >= 4 && line[3] == '-') {
#if NET8_0_OR_GREATER
                line = await reader.ReadLineAsync(token);
#else
                line = await reader.ReadLineAsync().WaitWithCancellation(token);
#endif
                if (line == null) {
                    break;
                }

                if (line.StartsWith(code, StringComparison.Ordinal)) {
                    lastLine = line;
                } else {
                    // Start of next response; ignore extra line
                    break;
                }
            }

            return lastLine;
        }
    }
}