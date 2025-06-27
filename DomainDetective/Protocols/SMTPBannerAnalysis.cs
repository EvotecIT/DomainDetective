using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
namespace DomainDetective {
    /// <summary>
    /// Captures SMTP greeting banners and validates expected hostname and software strings.
    /// </summary>
    public class SMTPBannerAnalysis {
        /// <summary>Result of a banner check.</summary>
        public class BannerResult {
            /// <summary>Initial banner line returned by the server.</summary>
            public string? Banner { get; init; }
            /// <summary>True when <see cref="SMTPBannerAnalysis.ExpectedHostname"/> is found in the banner.</summary>
            public bool HostnameMatch { get; init; }
            /// <summary>True when <see cref="SMTPBannerAnalysis.ExpectedSoftware"/> is found in the banner.</summary>
            public bool SoftwareMatch { get; init; }
        }

        /// <summary>Results for each host and port.</summary>
        public Dictionary<string, BannerResult> ServerResults { get; } = new();
        /// <summary>Connection timeout for banner retrieval.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Expected hostname that should appear in the banner.</summary>
        public string? ExpectedHostname { get; set; }
        /// <summary>Expected software string that should appear in the banner.</summary>
        public string? ExpectedSoftware { get; set; }

        /// <summary>Checks a single SMTP server banner.</summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            var result = await GetBanner(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = result;
        }

        /// <summary>Checks multiple hosts on the same port.</summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                ServerResults[$"{host}:{port}"] = await GetBanner(host, port, logger, cancellationToken);
            }
        }

        private async Task<BannerResult> GetBanner(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
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
                var banner = await reader.ReadLineAsync(timeoutCts.Token);
#else
                var banner = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
                timeoutCts.Token.ThrowIfCancellationRequested();
                try {
#if NET8_0_OR_GREATER
                    await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                    await writer.FlushAsync(timeoutCts.Token);
#else
                    await writer.WriteLineAsync("QUIT");
                    await writer.FlushAsync();
#endif
                    await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                } catch (IOException) {
                    // disconnect
                }
                bool hostMatch = !string.IsNullOrWhiteSpace(ExpectedHostname) && banner?.IndexOf(ExpectedHostname, StringComparison.OrdinalIgnoreCase) >= 0;
                bool softMatch = !string.IsNullOrWhiteSpace(ExpectedSoftware) && banner?.IndexOf(ExpectedSoftware, StringComparison.OrdinalIgnoreCase) >= 0;
                return new BannerResult { Banner = banner, HostnameMatch = hostMatch, SoftwareMatch = softMatch };
            } catch (TaskCanceledException ex) {
                throw new OperationCanceledException(ex.Message, ex, cancellationToken);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteError("SMTP banner check failed for {0}:{1} - {2}", host, port, ex.Message);
                return new BannerResult();
            }
        }
    }
}
