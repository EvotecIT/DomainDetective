using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries SOA record for a domain and performs analysis.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySOA(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            var soa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.SOA, cancellationToken: cancellationToken);
            SOAAnalysis.Subject = domainName;
            await SOAAnalysis.AnalyzeSoaRecords(soa, _logger);
        }

        /// <summary>
        /// Analyzes a raw SOA record.
        /// </summary>
        /// <param name="soaRecord">SOA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSOA(string soaRecord, CancellationToken cancellationToken = default) {
            await SOAAnalysis.AnalyzeSoaRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = soaRecord,
                    Type = DnsRecordType.SOA
                }
            }, _logger);
        }
    }
}
