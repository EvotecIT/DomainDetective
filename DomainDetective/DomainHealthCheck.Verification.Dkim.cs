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
        public Task VerifyDKIM(string domainName, string[] selectors, CancellationToken cancellationToken = default) {
            return VerifyDKIM(domainName, selectors, includeMissingSelectors: false, cancellationToken);
        }

        /// <summary>
        /// Verifies DKIM records for the specified domain.
        /// </summary>
        /// <param name="domainName">Domain to inspect.</param>
        /// <param name="selectors">Selectors to query or <c>null</c> to auto detect.</param>
        /// <param name="includeMissingSelectors">When <c>true</c>, <c>AnalysisResults</c> will include entries for selectors that have no published DKIM record and warnings will be logged for those missing records. When <c>false</c>, selectors with no published DKIM record are omitted from <c>AnalysisResults</c> and no warnings are logged for them.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDKIM(string domainName, string[] selectors, bool includeMissingSelectors, CancellationToken cancellationToken = default) {
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

            var adsp = await DnsConfiguration.QueryDNS(
                $"_adsp._domainkey.{domainName}",
                DnsRecordType.TXT,
                filter: string.Empty,
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
            if (adsp.Any()) {
                await DKIMAnalysis.AnalyzeAdspRecord(adsp, _logger);
            }

            var normalizedSelectors = selectors
                .Select(static selector => selector?.Trim())
                .Where(static selector => !string.IsNullOrWhiteSpace(selector))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Cast<string>()
                .ToArray();
            var results = new DnsAnswer[normalizedSelectors.Length][];
            var errors = new Exception?[normalizedSelectors.Length];
            using var concurrency = new SemaphoreSlim(Math.Max(1, DKIMAnalysis.SelectorQueryConcurrency));
            var queries = normalizedSelectors.Select(async (selector, index) => {
                await concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                try {
                    results[index] = await DnsConfiguration.QueryDNS(
                        name: $"{selector}._domainkey.{domainName}",
                        recordType: DnsRecordType.TXT,
                        filter: string.Empty,
                        includeAliasesInFilter: true,
                        cancellationToken: cancellationToken).ConfigureAwait(false);
                } catch (Exception ex) when (!cancellationToken.IsCancellationRequested && (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException)) {
                    errors[index] = ex;
                } finally {
                    concurrency.Release();
                }
            }).ToArray();
            await Task.WhenAll(queries).ConfigureAwait(false);

            for (var index = 0; index < normalizedSelectors.Length; index++) {
                var trimmedSelector = normalizedSelectors[index];
                if (errors[index] == null) {
                    var dkim = results[index] ?? Array.Empty<DnsAnswer>();
                    if (dkim.Any() || includeMissingSelectors) {
                        await DKIMAnalysis.AnalyzeDkimRecords(trimmedSelector, dkim, logger: _logger);
                    }
                } else {
                    // Treat network timeouts as transient in tests/CI: record no results and continue.
                    _logger.WriteWarningCode(DkimCodes.QueryFailed, "DKIM DNS query failed for selector {0} on {1}: {2}", trimmedSelector, domainName, errors[index]!.Message);
                }
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
