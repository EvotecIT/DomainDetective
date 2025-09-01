using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries NS records for a domain and performs analysis.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyNS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix) {
                return;
            }
            var ns = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.NS, cancellationToken: cancellationToken);
            NSAnalysis.Subject = domainName;
            await NSAnalysis.AnalyzeNsRecords(ns, _logger);
        }

        /// <summary>
        /// Analyzes a single NS record.
        /// </summary>
        /// <param name="nsRecord">NS record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckNS(string nsRecord, CancellationToken cancellationToken = default) {
            NSAnalysis.Subject = null;
            await NSAnalysis.AnalyzeNsRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = nsRecord,
                    Type = DnsRecordType.NS
                }
            }, _logger);
        }

        /// <summary>
        /// Analyzes multiple NS records.
        /// </summary>
        /// <param name="nsRecords">Collection of NS record texts.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckNS(List<string> nsRecords, CancellationToken cancellationToken = default) {
            NSAnalysis.Subject = null;
            var dnsResults = nsRecords.Select(record => new DnsAnswer {
                DataRaw = record,
            }).ToList();
            await NSAnalysis.AnalyzeNsRecords(dnsResults, _logger);
        }
    }
}
