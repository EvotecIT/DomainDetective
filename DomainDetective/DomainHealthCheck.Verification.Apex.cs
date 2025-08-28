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
        public async Task VerifyApexAddresses(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            // Apex address analysis is useful even for registrable domains; do not short-circuit on public suffix.

            // If a DNS override is supplied (common in tests), use it directly for A/AAAA to avoid resolver indirection.
            if (DnsConfiguration?.QueryDnsOverride != null) {
                var a = await DnsConfiguration.QueryDnsOverride(domainName, DnsRecordType.A);
                var aaaa = await DnsConfiguration.QueryDnsOverride(domainName, DnsRecordType.AAAA);
                await ApexAddressAnalysis.AnalyzeApexAnswers(a ?? Array.Empty<DnsAnswer>(), aaaa ?? Array.Empty<DnsAnswer>(), _logger);
                await ApexAddressAnalysis.AnalyzeReverseDnsAsync(domainName, _logger);
                await ApexAddressAnalysis.AnalyzeAsnAndRpkiAsync(domainName, _logger);
            } else {
                // Use the analysis pipeline which honors overrides on ApexAddressAnalysis.DnsConfiguration
                await ApexAddressAnalysis.AnalyzeAsync(domainName, _logger);
            }
        }
    }
}
