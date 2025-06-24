using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public class OpenRelayAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            var allows = await TryRelay(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = allows;
        }

        private static async Task<bool> TryRelay(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            using var client = new TcpClient();
            try {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(host, port, cancellationToken);
#else
                await client.ConnectAsync(host, port);
                cancellationToken.ThrowIfCancellationRequested();
#endif
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

#if NET8_0_OR_GREATER
                await reader.ReadLineAsync(cancellationToken);
#else
                await reader.ReadLineAsync();
                cancellationToken.ThrowIfCancellationRequested();
#endif
                cancellationToken.ThrowIfCancellationRequested();
                await writer.WriteLineAsync($"HELO example.com");
#if NET8_0_OR_GREATER
                await reader.ReadLineAsync(cancellationToken);
#else
                await reader.ReadLineAsync();
                cancellationToken.ThrowIfCancellationRequested();
#endif
                cancellationToken.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("MAIL FROM:<test@example.com>");
#if NET8_0_OR_GREATER
                var mailResp = await reader.ReadLineAsync(cancellationToken);
#else
                var mailResp = await reader.ReadLineAsync();
                cancellationToken.ThrowIfCancellationRequested();
#endif
                cancellationToken.ThrowIfCancellationRequested();
                await writer.WriteLineAsync("RCPT TO:<test@example.org>");
#if NET8_0_OR_GREATER
                var rcptResp = await reader.ReadLineAsync(cancellationToken);
                await writer.WriteLineAsync("QUIT".AsMemory(), cancellationToken);
                await writer.FlushAsync(cancellationToken);
                await reader.ReadLineAsync(cancellationToken);
#else
                var rcptResp = await reader.ReadLineAsync();
                await writer.WriteLineAsync("QUIT");
                await writer.FlushAsync();
                await reader.ReadLineAsync();
                cancellationToken.ThrowIfCancellationRequested();
#endif

                logger?.WriteVerbose($"MAIL FROM response: {mailResp}");
                logger?.WriteVerbose($"RCPT TO response: {rcptResp}");

                return mailResp != null && mailResp.StartsWith("250") && rcptResp != null && rcptResp.StartsWith("250");
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteError("Open relay check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            }
        }
    }
}