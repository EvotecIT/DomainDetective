using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries WHOIS information and IANA RDAP for a domain.
        /// </summary>
        public async Task CheckWHOIS(string domain, CancellationToken cancellationToken = default) {
            var timeout = WhoisAnalysis.Timeout;
            WhoisAnalysis = new WhoisAnalysis {
                Timeout = timeout,
                DnsConfiguration = DnsConfiguration
            };
            domain = NormalizeDomain(domain);
            UpdateIsPublicSuffix(domain);
            await WhoisAnalysis.QueryWhoisServer(domain, cancellationToken);
            await WhoisAnalysis.QueryIana(domain, cancellationToken);
        }

        /// <summary>
        /// Queries RDAP information for a domain.
        /// </summary>
        public async Task QueryRDAP(string domain, CancellationToken cancellationToken = default) {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(domain)) {
                throw new ArgumentNullException(nameof(domain));
            }

            domain = NormalizeDomain(domain);
            UpdateIsPublicSuffix(domain);
            await RdapAnalysis.Analyze(domain, _logger, cancellationToken);
        }
    }
}
