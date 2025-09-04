using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class TyposquattingNarrative
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

    public static Sections Build(TyposquattingAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"Typosquatting Report — {subj}";
        var subtitle = "Typosquatting Assessment";
        var category = "Brand Protection";
        var keywords = $"typosquatting, brand, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Typosquatting involves registering look-alike domains to deceive users or capture traffic.";
        var why = "Monitoring and defensively registering variants reduces impersonation risk.";

        var hi = new List<string>();
        var det = new List<string>();
        var active = analysis?.ActiveDomains ?? new List<string>();
        if (active.Count > 0)
        {
            hi.Add($"Active typosquat domains: {string.Join(", ", active)}");
            det.AddRange(active.Select(d => $"Active: {d}"));
        }
        else
        {
            hi.Add("No active typosquat domains detected.");
        }

        var available = (analysis?.Variants ?? new List<string>())
            .Except(active, StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (available.Count > 0)
        {
            det.Add("Available for defensive registration: " + string.Join(", ", available));
        }

        var refs = new List<string>
        {
            "https://en.wikipedia.org/wiki/Typosquatting"
        };

        var positives = new List<string>();
        var remediations = new List<string>();
        try
        {
            var groups = RecommendationEngine.GroupByCode(analysis?.Assessments ?? new List<Assessment>());
            foreach (var g in groups)
            {
                var msg = string.IsNullOrWhiteSpace(g.Advice?.Title)
                    ? g.Instances.FirstOrDefault()?.Message ?? g.Code
                    : g.Advice.Title;
                if (g.MaxSeverity == AssessmentSeverity.Info)
                {
                    positives.Add(msg);
                }
                else
                {
                    remediations.Add(msg);
                }
            }
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
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
