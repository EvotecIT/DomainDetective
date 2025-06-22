using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace DomainDetective {
    public class OpenRelayAnalysis {
        public Dictionary<string, bool> ServerResults { get; private set; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger) {
            var allows = await TryRelay(host, port, logger);
            ServerResults[$"{host}:{port}"] = allows;
        }

        private static async Task<bool> TryRelay(string host, int port, InternalLogger logger) {
            using var client = new TcpClient();
            try {
                await client.ConnectAsync(host, port);
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

                await reader.ReadLineAsync();
                await writer.WriteLineAsync($"HELO example.com");
                await reader.ReadLineAsync();
                await writer.WriteLineAsync("MAIL FROM:<test@example.com>");
                var mailResp = await reader.ReadLineAsync();
                await writer.WriteLineAsync("RCPT TO:<test@example.org>");
                var rcptResp = await reader.ReadLineAsync();
                await writer.WriteLineAsync("QUIT");

                logger?.WriteVerbose($"MAIL FROM response: {mailResp}");
                logger?.WriteVerbose($"RCPT TO response: {rcptResp}");

                return mailResp != null && mailResp.StartsWith("250") && rcptResp != null && rcptResp.StartsWith("250");
            } catch (Exception ex) {
                logger?.WriteError("Open relay check failed for {0}:{1} - {2}", host, port, ex.Message);
                return false;
            }
        }
    }
}
