using System;
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

        var highlights = new List<string>();
        var details = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        highlights.Add(arc.ArcHeadersFound ? "ARC headers present." : "No ARC headers present.");
        if (arc.ChainState == ArcChainState.Valid)
        {
            highlights.Add("ARC chain is valid and sequential.");
        }
        else if (arc.ChainState == ArcChainState.Invalid)
        {
            highlights.Add("ARC chain is invalid or incomplete.");
        }
        else
        {
            highlights.Add("ARC chain missing.");
        }

        if (arc.SealsIncludeSignatures)
        {
            highlights.Add("ARC seals include signatures.");
        }

        details.Add($"ARC-Seal headers: {arc.ArcSealHeaders.Count}");
        details.Add($"ARC-Authentication-Results headers: {arc.ArcAuthenticationResultsHeaders.Count}");

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc8617"
        };

        try
        {
            AssessmentSplit.SplitTitles(arc.Assessments ?? new List<Assessment>(), out positives, out remediations);
        }
        catch (Exception)
        {
            // Assessment splitting is best effort; narrative should still render even if it fails.
        }

        return new Sections
        {
            Title = title,
            Subtitle = subtitle,
            Category = category,
            Keywords = keywords,
            Creator = creator,
            Introduction = intro,
            WhyItMatters = why,
            Highlights = highlights,
            Details = details,
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }
}
