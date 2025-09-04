using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class ArcNarrative
{
    public sealed class Sections
    {
        public string Title { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string Category { get; init; } = string.Empty;
        public string Keywords { get; init; } = string.Empty;
        public string Creator { get; init; } = string.Empty;
        public string Introduction { get; init; } = string.Empty;
        public string WhyItMatters { get; init; } = string.Empty;
        public List<string> Highlights { get; init; } = new();
        public List<string> Details { get; init; } = new();
        public List<string> References { get; init; } = new();
        public List<string> Positives { get; init; } = new();
        public List<string> Remediations { get; init; } = new();
    }

    public static Sections Build(ARCAnalysis arc)
    {
        var title = "ARC Report";
        var subtitle = "ARC Assessment";
        var category = "Email Security";
        var keywords = "ARC, email, security, DomainDetective";
        var creator = "DomainDetective";
        var intro = "Authenticated Received Chain (ARC) preserves authentication results through intermediaries.";
        var why = "Valid ARC chains allow receivers to trust authentication results even after forwarding.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        hi.Add(arc.ArcHeadersFound ? "ARC headers present." : "No ARC headers present.");
        if (arc.ChainState == ArcChainState.Valid)
        {
            hi.Add("ARC chain is valid and sequential.");
        }
        else if (arc.ChainState == ArcChainState.Invalid)
        {
            hi.Add("ARC chain is invalid or incomplete.");
        }
        else
        {
            hi.Add("ARC chain missing.");
        }

        if (arc.ValidChain)
        {
            hi.Add("ARC seals include signatures.");
        }

        det.Add($"ARC-Seal headers: {arc.ArcSealHeaders.Count}");
        det.Add($"ARC-Authentication-Results headers: {arc.ArcAuthenticationResultsHeaders.Count}");

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc8617"
        };

        try
        {
            AssessmentSplit.SplitTitles(arc.Assessments ?? new List<Assessment>(), out positives, out remediations);
        }
        catch { }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }
}
