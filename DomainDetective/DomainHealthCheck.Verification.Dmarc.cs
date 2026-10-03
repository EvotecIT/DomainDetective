using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries DNS and analyzes DMARC records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyDMARC(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            if (IsPublicSuffix && DmarcDiscoveryMode == DmarcDiscoveryMode.LegacyPublicSuffix) {
                return;
            }
            DmarcAnalysis.Subject = domainName;
            if (DmarcDiscoveryMode == DmarcDiscoveryMode.DnsTreeWalk) {
                var discovery = new DmarcPolicyDiscovery((name, token) => DnsConfiguration.QueryPolicyDNS(
                    name, DnsRecordType.TXT, includeAliasesInFilter: true, cancellationToken: token));
                bool analyzed = false;
                try {
                    var result = await discovery.DiscoverAsync(domainName, cancellationToken).ConfigureAwait(false);
                    var policyDomainName = result.Policy?.Domain ?? domainName;
                    await DmarcAnalysis.AnalyzeDmarcRecords(result.Policy?.Answers ?? Array.Empty<DnsAnswer>(), _logger,
                        domainName, getOrgDomain: null, policyDomainName: policyDomainName,
                        getOrgDomainAsync: discovery.FindOrganizationalDomainAsync, cancellationToken: cancellationToken).ConfigureAwait(false);
                    analyzed = true;
                    DmarcAnalysis.OrganizationalDomain = result.OrganizationalDomain ?? DmarcAnalysis.OrganizationalDomain;
                    if (policyDomainName != domainName && DmarcAnalysis.IsPolicyValid && !string.IsNullOrEmpty(DmarcAnalysis.NonexistentPolicyShort)) {
                        // NXDOMAIN at _dmarc does not establish that the author domain is absent.
                        var existence = await DnsConfiguration.QueryDNSResponse(domainName, DnsRecordType.SOA,
                            cancellationToken: cancellationToken).ConfigureAwait(false);
                        if (!string.IsNullOrEmpty(existence.Error) || existence.Status != DnsResponseCode.NoError && existence.Status != DnsResponseCode.NXDomain)
                            throw new DnsQueryFailureException(domainName, DnsRecordType.SOA, existence);
                        DmarcAnalysis.SubjectDomainExists = existence.Status == DnsResponseCode.NoError;
                    }
                    DmarcAnalysis.EvaluatePolicyStrength(UseSubdomainPolicy || policyDomainName != domainName);
                    using var diagnostics = AssessmentCollector.ForAnalysis(_logger, DmarcAnalysis, category: "DMARC", target: domainName);
                    foreach (var rejected in result.Rejected) {
                        int count = rejected.Answers.Count(answer => answer.Type == DnsRecordType.TXT && DmarcAnalysis.IsDmarcPolicyRecord(answer.TxtConcatenatedData));
                        _logger.WriteWarningCode(count > 1 ? DmarcCodes.MultipleRecords : "DMARC.Record.SyntaxInvalid",
                            "DMARC records at {0} were discarded during discovery: {1}.", rejected.Domain, count > 1 ? "multiple policies" : "invalid tag syntax");
                    }
                } catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
                    throw;
                } catch (Exception ex) when (ex is DnsQueryFailureException || ex is TimeoutException || ex is System.Net.Http.HttpRequestException || ex is TaskCanceledException) {
                    if (!analyzed) await DmarcAnalysis.AnalyzeDmarcRecords(null, _logger, domainName).ConfigureAwait(false);
                    DmarcAnalysis.RecordDnsQueryFailure(ex, _logger);
                }
                return;
            }
            var dmarc = await DnsConfiguration.QueryPolicyDNS(
                "_dmarc." + domainName,
                DnsRecordType.TXT,
                "DMARC1",
                includeAliasesInFilter: true,
                cancellationToken: cancellationToken);
            var policyDomain = domainName;
            if (!dmarc.Any(answer => answer.Type == DnsRecordType.TXT)) {
                var organizationalDomain = _publicSuffixList.GetRegistrableDomain(domainName);
                if (!string.IsNullOrWhiteSpace(organizationalDomain) &&
                    !string.Equals(organizationalDomain, domainName, StringComparison.OrdinalIgnoreCase)) {
                    policyDomain = organizationalDomain;
                    dmarc = await DnsConfiguration.QueryPolicyDNS(
                        "_dmarc." + policyDomain,
                        DnsRecordType.TXT,
                        "DMARC1",
                        includeAliasesInFilter: true,
                        cancellationToken: cancellationToken);
                }
            }
            await DmarcAnalysis.AnalyzeDmarcRecords(dmarc, _logger, domainName, _publicSuffixList.GetRegistrableDomain, policyDomain);
            var inheritedPolicy = !string.Equals(policyDomain, domainName, StringComparison.OrdinalIgnoreCase);
            DmarcAnalysis.EvaluatePolicyStrength(UseSubdomainPolicy || inheritedPolicy);
        }

        /// <summary>
        /// Analyzes a raw DMARC record.
        /// </summary>
        /// <param name="dmarcRecord">DMARC record text.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckDMARC(string dmarcRecord, CancellationToken cancellationToken = default) {
            await DmarcAnalysis.AnalyzeDmarcRecords(new List<DnsAnswer> {
                new DnsAnswer {
                    DataRaw = dmarcRecord,
                    Type = DnsRecordType.TXT
                }
            }, _logger);
            DmarcAnalysis.EvaluatePolicyStrength(UseSubdomainPolicy);
        }
    }
}
