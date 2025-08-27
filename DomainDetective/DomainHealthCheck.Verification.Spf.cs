using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries DNS and analyzes SPF records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifySPF(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            SpfAnalysis.Subject = domainName;
            var spf = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.TXT, "SPF1", cancellationToken);
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
            await SpfAnalysis.GetFlattenedIpAnalysis(domainName, _logger);
            await SpfAnalysis.ComputeEffectiveSpfSendsAsync(_logger);
        }

        /// <summary>
        /// Analyzes a raw SPF record.
        /// </summary>
        /// <param name="spfRecord">SPF record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSPF(string spfRecord, CancellationToken cancellationToken = default) {
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = spfRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }
    }
}
