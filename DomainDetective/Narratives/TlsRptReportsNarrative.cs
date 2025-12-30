using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class TlsRptReportsNarrative
{
    public static NarrativeSections Build(string? subject)
    {
        var subj = string.IsNullOrWhiteSpace(subject) ? "Domain" : subject!;
        return new NarrativeSections
        {
            Title = $"TLS-RPT Reports — {subj}",
            Subtitle = "SMTP TLS Reporting",
            Category = "Mail Transport Security",
            Keywords = $"TLS-RPT, SMTP, TLS, DomainDetective, {subj}",
            Creator = "DomainDetective",
            Introduction = "TLS-RPT reports summarize delivery successes and failures related to SMTP TLS policy (for example, MTA-STS or DANE expectations) as observed by sending MTAs.",
            WhyItMatters = "These reports help identify mail transport misconfigurations (expired certificates, name mismatches, policy enforcement issues) and track remediation progress over time.",
            Highlights = new List<string>
            {
                "Failure rate trends across reporting windows.",
                "Top failure types and affected MX hosts."
            },
            References = new List<string>
            {
                "https://www.rfc-editor.org/rfc/rfc8460"
            }
        };
    }
}

