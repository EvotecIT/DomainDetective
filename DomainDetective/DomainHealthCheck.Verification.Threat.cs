using DnsClientX;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>Queries reputation services for threat listings.</summary>
        /// <param name="domainName">Domain or IP address to check.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyThreatIntel(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.THREATINTEL, () => VerifyThreatIntelDirectCore(domainName, cancellationToken));

        private async Task VerifyThreatIntelDirectCore(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            await ThreatIntelAnalysis.Analyze(domainName, GoogleSafeBrowsingApiKey, PhishTankApiKey, VirusTotalApiKey, _logger, cancellationToken);
        }

        /// <summary>Queries threat feeds for IP reputation.</summary>
        /// <param name="ipAddress">IP address to check.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyThreatFeed(string ipAddress, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.THREATFEED, () => VerifyThreatFeedDirectCore(ipAddress, cancellationToken));

        private async Task VerifyThreatFeedDirectCore(string ipAddress, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(ipAddress)) {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            await ThreatFeedAnalysis.Analyze(ipAddress, VirusTotalApiKey, AbuseIpDbApiKey, _logger, cancellationToken);
        }
    }
}
