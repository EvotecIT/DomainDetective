using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class OpenResolverNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(OpenResolverAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subject = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(resolver)" : analysis.Subject!;
        var title = $"Open Resolver Report — {subject}";
        var subtitle = "DNS Recursion Assessment";
        var category = "DNS Security";
        var keywords = $"open resolver, dns, recursion, amplification, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "Open resolver tests check whether DNS servers perform recursion for arbitrary clients.";
        var why = "Open resolvers can be abused for amplification attacks and cache poisoning.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        var details = analysis?.ServerDetails ?? new Dictionary<string, OpenResolverResult>();
        var total = details.Count;
        var openCount = details.Count(d => d.Value.IsOpenResolver);
        var closedCount = total - openCount;

        if (total > 0)
            hi.Add($"Servers tested: {total}");
        if (openCount > 0)
            hi.Add($"{openCount} server(s) allow recursion.");
        else
            hi.Add("No open resolvers detected.");
        if (closedCount > 0 && openCount > 0)
            hi.Add($"{closedCount} server(s) refuse recursion.");

        foreach (var kv in details)
        {
            var status = kv.Value.IsOpenResolver ? "open recursion" : "recursion disabled";
            det.Add($"{kv.Key}: {status}");
            if (kv.Value.ResponseBytes is int bytes)
                det.Add($"  Response size: {bytes} bytes");
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc5358"
        };

        try
        {
            var assess = assessments ?? analysis?.Assessments ?? new List<Assessment>();
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assess);
        }
        catch
        {
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
            Highlights = hi,
            Details = det,
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }
}

