using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Analyzes a raw TLSRPT record.
        /// </summary>
        /// <param name="tlsRptRecord">TLSRPT record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckTLSRPT(string tlsRptRecord, CancellationToken cancellationToken = default) {
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = tlsRptRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken);
        }

        /// <summary>
        /// Queries and analyzes TLSRPT records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyTLSRPT(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            TLSRPTAnalysis = new TLSRPTAnalysis { Subject = domainName };
            var tlsrpt = await DnsConfiguration.QueryDNS(
                "_smtp._tls." + domainName,
                DnsRecordType.TXT,
                filter: string.Empty,
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
            await TLSRPTAnalysis.AnalyzeTlsRptRecords(tlsrpt, _logger, cancellationToken);
        }
    }
}
