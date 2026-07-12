using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides open resolver narrative functionality.</summary>
public static class OpenResolverNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(OpenResolverAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjectCandidate = analysis?.Subject;
        string subject;
        if (subjectCandidate != null && !string.IsNullOrWhiteSpace(subjectCandidate))
        {
            subject = subjectCandidate;
        }
        else
        {
            subject = "(resolver)";
        }
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
        var openCount = details.Count(d => d.Value.Status == OpenResolverStatus.Open);
        var closedCount = details.Count(d => d.Value.Status == OpenResolverStatus.Closed);
        var failedCount = details.Count(d => d.Value.Status == OpenResolverStatus.Failed || d.Value.Status == OpenResolverStatus.Unknown);

        if (total > 0)
            hi.Add($"Servers tested: {total}");
        if (openCount > 0)
            hi.Add($"{openCount} server(s) allow recursion.");
        else if (failedCount == 0)
            hi.Add("No open resolvers detected.");
        if (closedCount > 0)
            hi.Add($"{closedCount} server(s) refuse recursion.");
        if (failedCount > 0)
            hi.Add($"{failedCount} server probe(s) were inconclusive or failed.");

        foreach (var kv in details)
        {
            var status = kv.Value.Status switch {
                OpenResolverStatus.Open => "open recursion",
                OpenResolverStatus.Closed => "recursion disabled",
                _ => $"probe failed{(string.IsNullOrWhiteSpace(kv.Value.Error) ? string.Empty : $": {kv.Value.Error}")}"
            };
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

