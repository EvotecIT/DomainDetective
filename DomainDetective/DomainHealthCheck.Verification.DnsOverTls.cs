using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck : Settings {
        /// <summary>
        /// Detects DNS over TLS (DoT) support for authoritative name servers (TCP/853 + TLS handshake).
        /// </summary>
        public async Task VerifyDnsOverTls(string domainName, CancellationToken cancellationToken = default) {
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

