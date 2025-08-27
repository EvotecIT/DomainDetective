using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Verifies DKIM records for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to inspect.</param>
        /// <param name="selectors">Selectors to query or <c>null</c> to auto detect.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDKIM(string domainName, string[] selectors, CancellationToken cancellationToken = default) {
            DKIMAnalysis.Reset();
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            DKIMAnalysis.Subject = domainName;
            if (selectors == null || selectors.Length == 0) {
                await DKIMAnalysis.QueryWellKnownSelectors(domainName, DnsConfiguration, _logger, cancellationToken);
                return;
            }

            var adsp = await DnsConfiguration.QueryDNS($"_adsp._domainkey.{domainName}", DnsRecordType.TXT, cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await DKIMAnalysis.AnalyzeAdspRecord(adsp, _logger);
            }

            foreach (var selector in selectors) {
                var trimmedSelector = selector?.Trim();
                if (string.IsNullOrEmpty(trimmedSelector)) {
                    continue;
                }
                cancellationToken.ThrowIfCancellationRequested();
                var dkim = await DnsConfiguration.QueryDNS(name: $"{trimmedSelector}._domainkey.{domainName}", recordType: DnsRecordType.TXT, filter: "DKIM1", cancellationToken: cancellationToken);
                await DKIMAnalysis.AnalyzeDkimRecords(trimmedSelector, dkim, logger: _logger);
            }
        }

        /// <summary>
        /// Analyzes a raw DKIM record.
        /// </summary>
        /// <param name="dkimRecord">DKIM record text.</param>
        /// <param name="selector">Selector associated with the record.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDKIM(string dkimRecord, string selector = "default", CancellationToken cancellationToken = default) {
            DKIMAnalysis.Reset();
            await DKIMAnalysis.AnalyzeDkimRecords(selector, new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dkimRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }
    }
}
