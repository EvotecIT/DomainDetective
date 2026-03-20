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
            DnsAnswer[] spf = Array.Empty<DnsAnswer>();
            try {
                spf = await DnsConfiguration.QueryDNS(
                    domainName,
                    DnsRecordType.TXT,
                    "SPF1",
                    includeAliasesInFilter: true,
                    cancellationToken: cancellationToken);
            } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                _logger.WriteWarningCode(SpfCodes.QueryFailed, "SPF DNS query failed for {0}: {1}", domainName, ex.Message);
                // proceed with empty results to keep tests deterministic on transient network failures
                spf = Array.Empty<DnsAnswer>();
            }
            await SpfAnalysis.AnalyzeSpfRecords(spf, _logger);
            await SpfAnalysis.GetFlattenedIpAnalysis(domainName, _logger);
            await SpfAnalysis.ComputeEffectiveSpfSendsAsync(_logger);

            // Wildcard SPF protection for subdomains (best-effort; only meaningful when apex is deny-all).
            if (SpfAnalysis.DenyAll) {
                try {
                    bool dmarcStrongForSubdomains = false;
                    if (string.Equals(DmarcAnalysis.Subject, domainName, StringComparison.OrdinalIgnoreCase) && DmarcAnalysis.DmarcRecordExists) {
                        var effective = !string.IsNullOrWhiteSpace(DmarcAnalysis.SubPolicyShort)
                            ? DmarcAnalysis.SubPolicyShort
                            : DmarcAnalysis.PolicyShort;
                        dmarcStrongForSubdomains = string.Equals(effective, "reject", StringComparison.OrdinalIgnoreCase);
                    }

                    var wildcard = "*." + domainName;
                    var wildcardSpf = await DnsConfiguration.QueryDNS(
                        wildcard,
                        DnsRecordType.TXT,
                        "SPF1",
                        includeAliasesInFilter: true,
                        cancellationToken: cancellationToken).ConfigureAwait(false);

                    bool hasWildcardSpf = wildcardSpf != null && wildcardSpf.Length > 0;
                    if (!hasWildcardSpf && !dmarcStrongForSubdomains) {
                        SpfAnalysis.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Warning,
                            Category = "SPF",
                            Code = SpfCodes.WildcardMissing,
                            Target = wildcard,
                            Message = $"Missing wildcard SPF for subdomains ({wildcard}). Subdomains without SPF can be spoofed; consider adding '*.domain TXT \"v=spf1 -all\"' or enforcing DMARC for subdomains."
                        });
                    } else if (hasWildcardSpf) {
                        SpfAnalysis.Assessments.Add(new Assessment {
                            Severity = AssessmentSeverity.Info,
                            Category = "SPF",
                            Code = SpfCodes.WildcardPresent,
                            Target = wildcard,
                            Message = $"Wildcard SPF record present for subdomains ({wildcard})."
                        });
                    }
                } catch (Exception ex) when (ex is TaskCanceledException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException) {
                    // keep analysis deterministic on transient network failures
                }
            }
        }

        /// <summary>
        /// Analyzes a raw SPF record.
        /// </summary>
        /// <param name="spfRecord">SPF record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckSPF(string spfRecord, CancellationToken cancellationToken = default) {
            SpfAnalysis.Subject ??= string.Empty;
            await SpfAnalysis.AnalyzeSpfRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = spfRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
        }
    }
}
