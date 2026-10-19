using DnsClientX;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries apex A/AAAA for a domain and performs analysis.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyApexAddresses(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.APEXADDRESS, () => VerifyApexAddressesDirectCore(domainName, cancellationToken));

        private async Task VerifyApexAddressesDirectCore(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            ApexAddressAnalysis.DnsConfiguration = DnsConfiguration;
            await ApexAddressAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken).ConfigureAwait(false);
        }
    }
}
