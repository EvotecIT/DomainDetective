using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class FlatteningServiceNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(FlatteningServiceAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis!.Subject!;
        var title = $"Flattening Service Report — {subj}";
        var subtitle = "Flattening Service Assessment";
        var category = "DNS";
        var keywords = $"flattening, dns, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Flattening services provide A and AAAA records for CNAMEs at the zone apex.";
        var why = "They simplify apex aliasing but can hide target changes and couple you to the provider.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No flattening data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.CnameRecordExists
            ? $"{subj} CNAME → {analysis.Target}."
            : $"{subj} has no CNAME record.");
        hi.Add(analysis.IsFlatteningService
            ? "CNAME uses a known flattening provider."
            : "No known flattening provider detected.");
        if (analysis.Addresses.Count > 0)
        {
            hi.Add($"Resolves to {string.Join(", ", analysis.Addresses)}.");
        }

        var refs = DefaultRefs();

        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out negatives, out remediations);
            }
        }
        catch (Exception ex)
        {
            _ = ex;
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

    private static List<string> DefaultRefs() => new()
    {
        "https://www.cloudflare.com/learning/dns/dns-records/dns-cname-record/"
    };
}

