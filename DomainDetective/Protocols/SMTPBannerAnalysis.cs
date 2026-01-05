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
    public class SMTPBannerAnalysis : IHasAssessments {
        /// <summary>Subject of the check (domain or host).</summary>
        public string? Subject { get; set; }
        private const int MaxBannerLength = 512;
        private const int MaxBannerTextLength = MaxBannerLength - 2; // exclude CRLF
        /// <summary>Result of a banner check.</summary>
        /// <para>Part of the DomainDetective project.</para>
        public class BannerResult {
            /// <summary>Initial banner line returned by the server.</summary>
            public string? Banner { get; init; }
            /// <summary>Queried host.</summary>
            public string Host { get; init; } = string.Empty;
            /// <summary>Queried port.</summary>
            public int Port { get; init; }
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
            /// <summary>Parsed greeting code (e.g., 220), when available.</summary>
            public int? GreetingCode { get; init; }
            /// <summary>Domain or host extracted from the banner, if present.</summary>
            public string? ServerDomain { get; init; }
            /// <summary>True when the banner was truncated to the maximum allowed size.</summary>
            public bool Truncated { get; init; }
            /// <summary>Milliseconds between connect and first banner line.</summary>
            public int? ResponseTimeMs { get; init; }
            /// <summary>True when banner mentions TLS capability.</summary>
            public bool TlsAdvertised { get; init; }
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

        /// <summary>Structured assessments captured during banner checks.</summary>
        public List<Assessment> Assessments { get; } = new();
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        private static readonly Regex _versionLeakRegex = new(
            @"(?:(?:Postfix\s*\d|Exim\s*\d|Sendmail\s*\d|Microsoft\s+ESMTP\s+MAIL\s+Service\s+\d|Courier\s*\d))",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

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
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "SMTPBANNER", target: $"{host}:{port}");
            using var client = new TcpClient();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
                await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };
                var sw = System.Diagnostics.Stopwatch.StartNew();
                var banner = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                sw.Stop();
                if (banner != null && banner.Length > MaxBannerTextLength) {
                    logger?.WriteWarningCode(SmtpBannerCodes.Truncated, "Banner from {0}:{1} exceeded {2} bytes and was truncated.", host, port, MaxBannerLength);
                    banner = banner.Substring(0, MaxBannerTextLength);    
                }
                timeoutCts.Token.ThrowIfCancellationRequested();
                try {
                    await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                    await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
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
                    logger?.WriteWarningCode(SmtpBannerCodes.FormatInvalid, $"Banner from {host}:{port} is not RFC 5321 compliant: {banner}");
                }
                if (banner != null && !startsWith220) {
                    logger?.WriteWarningCode(SmtpBannerCodes.Not220, "Greeting from {0}:{1} does not start with 220: {2}", host, port, banner);
                }
                if (banner != null && startsWith220 && !containsDomain) {
                    logger?.WriteWarningCode(SmtpBannerCodes.MissingDomain, "Banner from {0}:{1} lacks a domain name: {2}", host, port, banner);
                }
                bool hostMatch = !string.IsNullOrWhiteSpace(ExpectedHostname) && banner?.IndexOf(ExpectedHostname, StringComparison.OrdinalIgnoreCase) >= 0;
                bool softMatch = !string.IsNullOrWhiteSpace(ExpectedSoftware) && banner?.IndexOf(ExpectedSoftware, StringComparison.OrdinalIgnoreCase) >= 0;
                bool tlsAdvertised = banner?.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0;
                if (hostMatch) {
                    logger?.WriteInformationCode(SmtpBannerCodes.HostnameMatch, "Banner on {0}:{1} includes expected hostname '{2}'.", host, port, ExpectedHostname);
                }
                if (tlsAdvertised) {
                    logger?.WriteInformationCode(SmtpBannerCodes.TlsAdvertised, "Banner on {0}:{1} advertises TLS support.", host, port);
                }
                if (!string.IsNullOrWhiteSpace(ExpectedSoftware) && banner != null && !softMatch) {
                    logger?.WriteWarningCode(SmtpBannerCodes.UnexpectedSoftware, "Banner software on {0}:{1} does not match expectation '{2}': {3}", host, port, ExpectedSoftware, banner);
                }
                if (banner != null && _versionLeakRegex.IsMatch(banner)) {
                    logger?.WriteWarningCode(SmtpBannerCodes.VersionLeaked, "SMTP banner on {0}:{1} exposes software version: {2}", host, port, banner);
                }
                int? code = null;
                if (banner != null && banner.Length >= 3 && int.TryParse(banner.Substring(0, 3), out var parsed))
                {
                    code = parsed;
                }
                return new BannerResult {
                    Banner = banner,
                    Host = host,
                    Port = port,
                    HostnameMatch = hostMatch,
                    SoftwareMatch = softMatch,
                    StartsWith220 = startsWith220,
                    ContainsDomain = containsDomain,
                    ValidFormat = validFormat,
                    GreetingCode = code,
                    ServerDomain = domain,
                    Truncated = banner != null && banner.Length >= MaxBannerTextLength,
                    ResponseTimeMs = (int)sw.ElapsedMilliseconds,
                    TlsAdvertised = tlsAdvertised
                };
            } catch (TaskCanceledException ex) {
                throw new OperationCanceledException(ex.Message, ex, cancellationToken);
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                logger?.WriteErrorCode(SmtpBannerCodes.CheckFailed, "SMTP banner check failed for {0}:{1} - {2}", host, port, ex.Message);
                return new BannerResult();
            }
        }
    }
}
