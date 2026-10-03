using DnsClientX;
using DomainDetective.Helpers;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DmarcAnalysis {
    /// <summary>Organizational domain established by RFC 9989 discovery, when determined.</summary>
    public string? OrganizationalDomain { get; internal set; }
    /// <summary>Applicable policy, including the RFC 9989 p=none fallback for invalid policy tags with valid rua.</summary>
    public string EffectivePolicyShort { get; private set; } = string.Empty;
    /// <summary>Whether the RFC 9989 test-mode tag requests one level less enforcement.</summary>
    public bool IsTestMode { get; private set; }
    /// <summary>Observed existence of the author domain when choosing inherited np versus sp policy.</summary>
    public bool? SubjectDomainExists { get; internal set; }

    /// <summary>Applicable policy for existing subdomains, including inherited sp and test-mode reduction.</summary>
    public string EffectiveSubdomainPolicyShort => DnsQueryFailed || !DmarcRecordExists || MultipleRecords ? string.Empty
        : IsPolicyValid ? PolicyWithTestMode(string.IsNullOrWhiteSpace(SubPolicyShort) ? PolicyShort : SubPolicyShort)
        : EffectivePolicyShort == "none" ? "none" : string.Empty;

    private string PolicyWithTestMode(string policy) => !IsTestMode ? policy : policy switch {
        "reject" => "quarantine",
        "quarantine" => "none",
        _ => policy
    };
    /// <summary>True when discovery failed rather than proving policy absence.</summary>
    public bool DnsQueryFailed { get; private set; }
    /// <summary>DNS failure evidence from the latest discovery.</summary>
    public string? DnsQueryError { get; private set; }

    internal void RecordDnsQueryFailure(Exception exception, InternalLogger logger) {
        DnsQueryFailed = true;
        DnsQueryError = exception.Message;
        EffectivePolicyShort = string.Empty;
        WeakPolicy = false;
        PolicyRecommendation = string.Empty;
        Assessments.RemoveAll(assessment => assessment.Code == DmarcCodes.PolicyReject || assessment.Code == DmarcCodes.PolicyQuarantine
            || assessment.Code == "DMARC.Policy.Recommendation");
        Advisory = "DMARC policy discovery failed; policy absence was not established.";
        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "DMARC", target: Subject);
        logger.WriteWarningCode(DmarcCodes.QueryFailed, "DMARC DNS query failed for {0}: {1}", Subject ?? string.Empty, exception.Message);
    }

    /// <summary>Evaluates authenticated identifiers using RFC 9989 DNS organizational boundaries.</summary>
    /// <remarks>For RFC 7489/PSL compatibility, use the synchronous resolver-supplied EvaluateAlignment overload.</remarks>
    public async Task EvaluateAlignmentAsync(string fromDomain, string? spfDomain, string? dkimDomain,
        CancellationToken cancellationToken = default) {
        SpfAligned = false;
        DkimAligned = false;
        cancellationToken.ThrowIfCancellationRequested();
        fromDomain = DomainHelper.ValidateIdn(fromDomain);
        if (!DmarcRecordExists || MultipleRecords || string.IsNullOrEmpty(EffectivePolicyShort)) return;
        var discovery = new DmarcPolicyDiscovery(async (name, token) => {
            token.ThrowIfCancellationRequested();
            if (QueryDnsOverride != null) {
                var answers = await QueryDnsOverride(name, DnsRecordType.TXT).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                return answers;
            }
            return await DnsConfiguration.QueryPolicyDNS(name, DnsRecordType.TXT, cancellationToken: token).ConfigureAwait(false);
        });
        string? fromOrg = null;
        async Task<bool> Align(string? authenticated, string mode) {
            if (string.IsNullOrWhiteSpace(authenticated)) return false;
            authenticated = DomainHelper.ValidateIdn(authenticated!);
            if (string.Equals(fromDomain.TrimEnd('.'), authenticated!.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)) return true;
            if (mode == "s") return false;
            fromOrg ??= await discovery.FindOrganizationalDomainAsync(fromDomain, cancellationToken).ConfigureAwait(false);
            string otherOrg = await discovery.FindOrganizationalDomainAsync(authenticated!, cancellationToken).ConfigureAwait(false);
            return string.Equals(fromOrg, otherOrg, StringComparison.OrdinalIgnoreCase);
        }
        SpfAligned = await Align(spfDomain, SpfAShort).ConfigureAwait(false);
        DkimAligned = await Align(dkimDomain, DkimAShort).ConfigureAwait(false);
        OrganizationalDomain = fromOrg ?? OrganizationalDomain;
    }
        /// <summary>
        /// Evaluates SPF and DKIM alignment for the provided domains.
        /// </summary>
        /// <param name="fromDomain">Domain from the RFC5322.From header.</param>
        /// <param name="spfDomain">Domain authenticated via SPF.</param>
        /// <param name="dkimDomain">Domain from the DKIM signature.</param>
        /// <param name="getOrgDomain">Function returning the organisational domain for a given input.</param>
        public void EvaluateAlignment(string fromDomain, string? spfDomain, string? dkimDomain, Func<string, string> getOrgDomain) {
            if (fromDomain == null) {
                throw new ArgumentNullException(nameof(fromDomain));
            }
            if (getOrgDomain == null) {
                throw new ArgumentNullException(nameof(getOrgDomain));
            }

            var fromOrg = getOrgDomain(fromDomain);
            var spfPolicy = string.IsNullOrEmpty(SpfAShort) ? "r" : SpfAShort;
            var dkimPolicy = string.IsNullOrEmpty(DkimAShort) ? "r" : DkimAShort;

            if (!string.IsNullOrWhiteSpace(spfDomain)) {
                var spfOrg = getOrgDomain(spfDomain!);
                SpfAligned = spfPolicy == "s"
                    ? string.Equals(fromDomain, spfDomain, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(fromOrg, spfOrg, StringComparison.OrdinalIgnoreCase);
            } else {
                SpfAligned = false;
            }

            if (!string.IsNullOrWhiteSpace(dkimDomain)) {
                var dkimOrg = getOrgDomain(dkimDomain!);
                DkimAligned = dkimPolicy == "s"
                    ? string.Equals(fromDomain, dkimDomain, StringComparison.OrdinalIgnoreCase)
                    : string.Equals(fromOrg, dkimOrg, StringComparison.OrdinalIgnoreCase);
            } else {
                DkimAligned = false;
            }
        }


}
