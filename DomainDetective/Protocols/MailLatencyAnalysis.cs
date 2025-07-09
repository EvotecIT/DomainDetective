using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Measures connection and banner retrieval latencies of SMTP servers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class MailLatencyAnalysis {
        /// <summary>Results of a latency check.</summary>
        public class LatencyResult {
            /// <summary>True when the connection succeeded.</summary>
            public bool ConnectSuccess { get; init; }
            /// <summary>True when a banner line was read.</summary>
            public bool BannerSuccess { get; init; }
            /// <summary>Time taken to establish the connection.</summary>
            public TimeSpan ConnectTime { get; init; }
            /// <summary>Time taken to read the banner after connecting.</summary>
            public TimeSpan BannerTime { get; init; }
        }

        /// <summary>Results for each server.</summary>
        public Dictionary<string, LatencyResult> ServerResults { get; } = new();
        /// <summary>Maximum wait time for connection and banner.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Checks a single host.</summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            ServerResults[$"{host}:{port}"] = await MeasureLatency(host, port, logger, cancellationToken);
        }

        /// <summary>Checks multiple hosts on the same port.</summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                ServerResults[$"{host}:{port}"] = await MeasureLatency(host, port, logger, cancellationToken);
            }
        }

        private async Task<LatencyResult> MeasureLatency(string host, int port, InternalLogger logger, CancellationToken token) {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
            var connectSw = Stopwatch.StartNew();
            try {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(host, port, cts.Token);
#else
                await client.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
#endif
                connectSw.Stop();
                var bannerSw = Stopwatch.StartNew();
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };
#if NET8_0_OR_GREATER
                var banner = await reader.ReadLineAsync(cts.Token);
#else
                var banner = await reader.ReadLineAsync().WaitWithCancellation(cts.Token);
#endif
                bannerSw.Stop();
                try {
                    await writer.WriteLineAsync("QUIT").WaitWithCancellation(cts.Token);
                    await writer.FlushAsync().WaitWithCancellation(cts.Token);
                    await reader.ReadLineAsync().WaitWithCancellation(cts.Token);
                } catch (IOException) { }
                return new LatencyResult {
                    ConnectSuccess = true,
                    BannerSuccess = banner != null,
                    ConnectTime = connectSw.Elapsed,
                    BannerTime = bannerSw.Elapsed
                };
            } catch (Exception ex) when (ex is SocketException || ex is IOException || ex is OperationCanceledException || ex is TaskCanceledException) {
                connectSw.Stop();
                logger?.WriteVerbose("Mail latency check failed for {0}:{1} - {2}", host, port, ex.Message);
                return new LatencyResult {
                    ConnectSuccess = client.Connected,
                    BannerSuccess = false,
                    ConnectTime = connectSw.Elapsed,
                    BannerTime = TimeSpan.Zero
                };
            }
        }
    }
}
