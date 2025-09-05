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
    public class MailLatencyAnalysis : IHasAssessments {
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
        /// <summary>Acceptable connection latency threshold.</summary>
        public TimeSpan ConnectThreshold { get; set; } = TimeSpan.FromMilliseconds(500);
        /// <summary>Acceptable banner latency threshold.</summary>
        public TimeSpan BannerThreshold { get; set; } = TimeSpan.FromMilliseconds(1000);
        /// <summary>Captured assessments during analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>Checks a single host.</summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            lock (ServerResults) {
                ServerResults.Clear();
            }
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "MAILLATENCY", target: $"{host}:{port}");
            var result = await MeasureLatency(host, port, logger, cancellationToken);
            lock (ServerResults) {
                ServerResults[$"{host}:{port}"] = result;
            }
        }

        /// <summary>Checks multiple hosts on the same port.</summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            lock (ServerResults) {
                ServerResults.Clear();
            }
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "MAILLATENCY", target: $"{host}:{port}");
                var result = await MeasureLatency(host, port, logger, cancellationToken);
                lock (ServerResults) {
                    ServerResults[$"{host}:{port}"] = result;
                }
            }
        }

        private async Task<LatencyResult> MeasureLatency(string host, int port, InternalLogger logger, CancellationToken token) {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            cts.CancelAfter(Timeout);
            var sw = Stopwatch.StartNew();
            TimeSpan connectElapsed = TimeSpan.Zero;
            try {
#if NET6_0_OR_GREATER
                await client.ConnectAsync(host, port, cts.Token);
#else
                await client.ConnectAsync(host, port).WaitWithCancellation(cts.Token);
#endif
                connectElapsed = sw.Elapsed;
                var bannerStart = sw.Elapsed;
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };
#if NET8_0_OR_GREATER
                var banner = await reader.ReadLineAsync(cts.Token);
#else
                var banner = await reader.ReadLineAsync().WaitWithCancellation(cts.Token);
#endif
                var bannerElapsed = sw.Elapsed;
                try {
                    await writer.WriteLineAsync("QUIT").WaitWithCancellation(cts.Token);
                    await writer.FlushAsync().WaitWithCancellation(cts.Token);
                    await reader.ReadLineAsync().WaitWithCancellation(cts.Token);
                } catch (IOException) { }
                var result = new LatencyResult {
                    ConnectSuccess = true,
                    BannerSuccess = banner != null,
                    ConnectTime = connectElapsed,
                    BannerTime = bannerElapsed - bannerStart
                };
                if (result.ConnectSuccess && result.ConnectTime <= ConnectThreshold) {
                    logger?.WriteInformationCode(MailLatencyCodes.ConnectUnderThreshold, "Connection to {0}:{1} completed in {2} ms", host, port, (int)result.ConnectTime.TotalMilliseconds);
                }
                if (result.BannerSuccess && result.BannerTime <= BannerThreshold) {
                    logger?.WriteInformationCode(MailLatencyCodes.BannerUnderThreshold, "Banner from {0}:{1} received in {2} ms", host, port, (int)result.BannerTime.TotalMilliseconds);
                }
                return result;
            } catch (Exception ex) when (ex is SocketException || ex is IOException || ex is OperationCanceledException || ex is TaskCanceledException) {
                logger?.WriteVerbose("Mail latency check failed for {0}:{1} - {2}", host, port, ex.Message);
                return new LatencyResult {
                    ConnectSuccess = client.Connected,
                    BannerSuccess = false,
                    ConnectTime = connectElapsed == TimeSpan.Zero ? sw.Elapsed : connectElapsed,
                    BannerTime = TimeSpan.Zero
                };
            }
        }
    }
}
