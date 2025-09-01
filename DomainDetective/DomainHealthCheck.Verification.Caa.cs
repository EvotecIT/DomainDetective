using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries CAA records for a domain and performs analysis.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyCAA(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            CAAAnalysis.Subject = domainName;
            var caa = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.CAA, cancellationToken: cancellationToken);
            await CAAAnalysis.AnalyzeCAARecords(caa, _logger);
        }

        /// <summary>
        /// Analyzes a single CAA record.
        /// </summary>
        /// <param name="caaRecord">CAA record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckCAA(string caaRecord, CancellationToken cancellationToken = default) {
            await CAAAnalysis.AnalyzeCAARecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = caaRecord,
                    Type = DnsRecordType.CAA
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes multiple CAA records.
        /// </summary>
        /// <param name="caaRecords">Collection of CAA record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckCAA(List<string> caaRecords, CancellationToken cancellationToken = default) {
            var dnsResults = caaRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }
    }
}
