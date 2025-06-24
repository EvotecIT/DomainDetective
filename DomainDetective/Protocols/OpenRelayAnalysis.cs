using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public class OpenRelayAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            var allows = await TryRelay(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = allows;
        }

        private async Task<bool> TryRelay(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
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

                return mailResp != null && mailResp.StartsWith("250") && rcptResp != null && rcptResp.StartsWith("250");
            } catch (TaskCanceledException ex) {
                throw new OperationCanceledException(ex.Message, ex, cancellationToken);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteError("Open relay check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            }
        }
    }
}