using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class RegistrationNarrative
{
    public static NarrativeSections Build(string? subject)
    {
        var subj = string.IsNullOrWhiteSpace(subject) ? "Domain" : subject!;
        return new NarrativeSections
        {
            Title = $"Registration Snapshot & Drift — {subj}",
            Subtitle = "WHOIS / RDAP",
            Category = "Registration",
            Keywords = $"WHOIS, RDAP, registration, drift, DomainDetective, {subj}",
            Creator = "DomainDetective",
            Introduction = "Domain registration data (WHOIS/RDAP) describes who manages the domain (registrar), important lifecycle dates (creation/expiry), and delegation details (name servers).",
            WhyItMatters = "Unexpected changes to registrar, expiry, name servers, or hold statuses can indicate transfer activity, misconfiguration, or potential domain takeover risks. Tracking drift over time helps detect changes early.",
            Highlights = new List<string>
            {
                "Unified snapshot from RDAP-first with WHOIS fallback.",
                "Structured drift (registrar, expiry, name servers, status) between snapshots."
            },
            References = new List<string>
            {
                "https://www.rfc-editor.org/rfc/rfc7483",
                "https://www.rfc-editor.org/rfc/rfc3912"
            }
        };
    }
}

