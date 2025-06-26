using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public class OpenRelayAnalysis {
        public Dictionary<string, OpenRelayStatus> ServerResults { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            using var client = new TcpClient();
            var status = await TryRelay(client, host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = status;
        }

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

#if NET8_0_OR_GREATER
                await reader.ReadLineAsync(timeoutCts.Token);
#else
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
#if NET8_0_OR_GREATER
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"HELO example.com");
                await reader.ReadLineAsync(timeoutCts.Token);
#else
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"HELO example.com");
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("MAIL FROM:<test@example.com>");
#if NET8_0_OR_GREATER
                var mailResp = await reader.ReadLineAsync(timeoutCts.Token);
#else
                var mailResp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
                timeoutCts.Token.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("RCPT TO:<test@example.org>");
#if NET8_0_OR_GREATER
                var rcptResp = await reader.ReadLineAsync(timeoutCts.Token);
                await writer.WriteLineAsync("QUIT".AsMemory(), timeoutCts.Token);
                await writer.FlushAsync(timeoutCts.Token);
                await reader.ReadLineAsync(timeoutCts.Token);
#else
                var rcptResp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif

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
    }
}