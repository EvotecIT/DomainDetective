using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class CnameNarrative
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

    public static Sections Build(CnameAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"CNAME Report — {subj}";
        var subtitle = "CNAME Assessment";
        var category = "DNS";
        var keywords = $"CNAME, dns, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "CNAME records map a hostname to another name. This analysis follows the chain to its final target and checks for resolution and loops.";
        var why = "Valid aliases improve reliability, while loops or dangling targets can break services and enable takeovers.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No CNAME data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.CnameRecordExists
            ? $"{subj} CNAME → {analysis.Target}."
            : $"{subj} has no CNAME record.");
        hi.Add(analysis.LoopDetected
            ? "CNAME loop detected."
            : "No CNAME loop detected.");
        hi.Add(analysis.TargetResolves
            ? "CNAME target resolves."
            : "CNAME target does not resolve.");

        var refs = DefaultRefs();

        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
            }
        }
        catch (Exception ex)
        {
            // Assessments are optional; ignore failures during splitting.
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
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://en.wikipedia.org/wiki/CNAME_record"
    };
}
