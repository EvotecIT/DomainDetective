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
            DnsAnswer[] caa = Array.Empty<DnsAnswer>();
            var candidate = domainName;
            while (!string.IsNullOrWhiteSpace(candidate)) {
                caa = await DnsConfiguration.QueryDNS(candidate, DnsRecordType.CAA, cancellationToken: cancellationToken);
                caa = caa.Where(answer => answer.Type == DnsRecordType.CAA).ToArray();
                if (caa.Length > 0) {
                    for (var index = 0; index < caa.Length; index++) {
                        if (string.IsNullOrWhiteSpace(caa[index].Name)) {
                            var answer = caa[index];
                            answer.Name = candidate;
                            caa[index] = answer;
                        }
                    }
                    break;
                }

                var separator = candidate.IndexOf('.');
                if (separator < 0 || separator == candidate.Length - 1) {
                    break;
                }
                candidate = candidate.Substring(separator + 1);
            }
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
                Type = DnsRecordType.CAA
            }).ToList();

            await CAAAnalysis.AnalyzeCAARecords(dnsResults, _logger);
        }
    }
}
