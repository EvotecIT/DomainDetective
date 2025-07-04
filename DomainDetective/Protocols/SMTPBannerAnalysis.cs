using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
namespace DomainDetective {
    /// <summary>
    /// Captures SMTP greeting banners and validates expected hostname and software strings.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SMTPBannerAnalysis {
        private const int MaxBannerLength = 512;
        private const int MaxBannerTextLength = MaxBannerLength - 2; // exclude CRLF
        /// <summary>Result of a banner check.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class BannerResult {
            /// <summary>Initial banner line returned by the server.</summary>
            public string? Banner { get; init; }
            /// <summary>True when <see cref="SMTPBannerAnalysis.ExpectedHostname"/> is found in the banner.</summary>
            public bool HostnameMatch { get; init; }
            /// <summary>True when <see cref="SMTPBannerAnalysis.ExpectedSoftware"/> is found in the banner.</summary>
            public bool SoftwareMatch { get; init; }
            /// <summary>True when banner begins with the 220 greeting code.</summary>
            public bool StartsWith220 { get; init; }
            /// <summary>True when banner contains a domain name after the greeting code.</summary>
            public bool ContainsDomain { get; init; }
            /// <summary>True when the banner conforms to RFC 5321 format.</summary>
            public bool ValidFormat { get; init; }
        }

        private static readonly Regex _labelRegex = new(
            "^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
            RegexOptions.Compiled);

        private static bool IsValidDomain(string domain) {
            if (domain.StartsWith("[") && domain.EndsWith("]", StringComparison.Ordinal)) {
                return true;
            }

            foreach (var label in domain.Split('.')) {
                if (!_labelRegex.IsMatch(label)) {
                    return false;
                }
            }

            return true;
        }

        private static bool IsValidBannerFormat(string? banner) {
            if (string.IsNullOrWhiteSpace(banner)) {
                return false;
            }

            var match = Regex.Match(banner, "^220(?:-|\\s)(\\S+)");
            if (!match.Success) {
                return false;
            }

            return IsValidDomain(match.Groups[1].Value);
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
                if (banner != null && banner.Length > MaxBannerTextLength) {
                    logger?.WriteWarning("Banner from {0}:{1} exceeded {2} bytes and was truncated.", host, port, MaxBannerLength);
                    banner = banner.Substring(0, MaxBannerTextLength);
                }
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
                bool startsWith220 = banner?.StartsWith("220", StringComparison.Ordinal) ?? false;
                string? domain = null;
                if (startsWith220 && banner != null) {
                    var parts = banner.Split(new[] { ' ' }, 3, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length > 1 && !string.IsNullOrWhiteSpace(parts[1])) {
                        domain = parts[1];
                    }
                }
                bool containsDomain = !string.IsNullOrWhiteSpace(domain);
                bool validFormat = IsValidBannerFormat(banner);
                if (!validFormat && banner != null) {
                    logger?.WriteWarning($"Banner from {host}:{port} is not RFC 5321 compliant: {banner}");
                }
                bool hostMatch = !string.IsNullOrWhiteSpace(ExpectedHostname) && banner?.IndexOf(ExpectedHostname, StringComparison.OrdinalIgnoreCase) >= 0;
                bool softMatch = !string.IsNullOrWhiteSpace(ExpectedSoftware) && banner?.IndexOf(ExpectedSoftware, StringComparison.OrdinalIgnoreCase) >= 0;
                return new BannerResult { Banner = banner, HostnameMatch = hostMatch, SoftwareMatch = softMatch, StartsWith220 = startsWith220, ContainsDomain = containsDomain, ValidFormat = validFormat };
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
