using DnsClientX;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Validates RPKI origins for domain IPs.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyRPKI(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.RPKI, () => VerifyRPKIDirectCore(domainName, cancellationToken));

        private async Task VerifyRPKIDirectCore(string domainName, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            RpkiAnalysis.DnsConfiguration = DnsConfiguration;
            await RpkiAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
