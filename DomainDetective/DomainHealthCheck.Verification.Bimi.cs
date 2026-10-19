using DnsClientX;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Analyzes a raw BIMI record.
        /// </summary>
        /// <param name="bimiRecord">BIMI record text.</param>
        /// <param name="skipIndicatorDownload">When true, do not download the SVG indicator.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task CheckBIMI(string bimiRecord, bool skipIndicatorDownload = false, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.BIMI, () => CheckBIMIDirectCore(bimiRecord, skipIndicatorDownload, cancellationToken), cancellationToken);

        private async Task CheckBIMIDirectCore(string bimiRecord, bool skipIndicatorDownload = false, CancellationToken cancellationToken = default) {
            BimiAnalysis.SkipIndicatorDownload = skipIndicatorDownload;
            await BimiAnalysis.AnalyzeBimiRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = bimiRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger, cancellationToken: cancellationToken);
        }

        /// <summary>
        /// Queries and analyzes BIMI records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="skipIndicatorDownload">When true, do not download the SVG indicator.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public Task VerifyBIMI(string domainName, bool skipIndicatorDownload = false, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.BIMI, () => VerifyBIMIDirectCore(domainName, skipIndicatorDownload, cancellationToken), cancellationToken, ownerDomain: domainName);

        private async Task VerifyBIMIDirectCore(string domainName, bool skipIndicatorDownload = false, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            BimiAnalysis = new BimiAnalysis { SkipIndicatorDownload = skipIndicatorDownload };
            BimiAnalysis.Subject = domainName;
            var bimi = await DnsConfiguration.QueryDNS(
                $"default._bimi.{domainName}",
                DnsRecordType.TXT,
                filter: string.Empty,
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
            await BimiAnalysis.AnalyzeBimiRecords(bimi, _logger, cancellationToken: cancellationToken);
        }
    }
}
