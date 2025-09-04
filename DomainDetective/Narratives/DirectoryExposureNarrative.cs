using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class DirectoryExposureNarrative
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

    public static Sections Build(DirectoryExposureAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"Directory Listing Report — {subj}";
        var subtitle = "Directory Exposure Assessment";
        var category = "Web Security";
        var keywords = $"directory listing, web, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Web servers may expose sensitive files when directory browsing is enabled.";
        var why = "Disabling directory listing reduces information disclosure and mitigates abuse.";

        var hi = new List<string>();
        var det = new List<string>();
        if (analysis?.ExposedPaths != null && analysis.ExposedPaths.Count > 0)
        {
            hi.Add($"Exposed paths: {string.Join(", ", analysis.ExposedPaths)}");
            det.AddRange(analysis.ExposedPaths.Select(p => $"Exposed: {p}"));
        }
        else
        {
            hi.Add("No exposed directories detected.");
        }

        var refs = new List<string> {
            "https://owasp.org/www-project-top-ten/",
            "https://developer.mozilla.org/docs/Web/Security/Directory_listing"
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
