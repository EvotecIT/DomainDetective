using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
        /// <summary>
        /// Detects DNS over TLS (DoT) support for authoritative name servers (TCP/853 + TLS handshake).
        /// </summary>
        public Task VerifyDnsOverTls(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.DNSOVERTLS, () => VerifyDnsOverTlsDirectCore(domainName, cancellationToken));

        private async Task VerifyDnsOverTlsDirectCore(string domainName, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }

            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }

            await DnsOverTlsAnalysis.Analyze(domainName, _logger, cancellationToken).ConfigureAwait(false);
        }
    }
}

