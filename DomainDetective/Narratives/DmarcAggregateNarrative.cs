using System.Collections.Generic;

namespace DomainDetective.Narratives;

/// <summary>Provides dmarc aggregate narrative functionality.</summary>
public static class DmarcAggregateNarrative
{
    /// <summary>Executes the build operation.</summary>
    public static NarrativeSections Build(string? subject)
    {
        var subj = string.IsNullOrWhiteSpace(subject) ? "Domain" : subject!;
        return new NarrativeSections
        {
            Title = $"DMARC Aggregate Reports — {subj}",
            Subtitle = "DMARC Aggregate (RUA)",
            Category = "Email Authentication",
            Keywords = $"DMARC, aggregate, RUA, DomainDetective, {subj}",
            Creator = "DomainDetective",
            Introduction = "DMARC aggregate (RUA) reports provide a periodic summary of how receivers evaluated SPF/DKIM alignment for mail that claims to be from your domain.",
            WhyItMatters = "They help measure authentication success rates, identify unauthorized or misconfigured senders, and support safer DMARC enforcement decisions based on real traffic.",
            Highlights = new List<string>
            {
                "Pass/fail trends across reporting windows.",
                "Top failing sources and alignment gaps."
            },
            References = new List<string>
            {
                "https://www.rfc-editor.org/rfc/rfc7489"
            }
        };
    }
}

