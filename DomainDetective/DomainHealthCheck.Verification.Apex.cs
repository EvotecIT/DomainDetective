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
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }

            var a = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.A, cancellationToken: cancellationToken);
            var aaaa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.AAAA, cancellationToken: cancellationToken);
            await ApexAddressAnalysis.AnalyzeApexAnswers(a, aaaa, _logger);
        }
    }
}

