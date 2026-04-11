using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides arc narrative functionality.</summary>
public static class ArcNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
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
        var negatives = new List<string>();
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
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(arc.Assessments ?? new List<Assessment>());
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
            Negatives = negatives,
            Remediations = remediations
        };
    }
}
