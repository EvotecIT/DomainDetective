using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class DirectoryExposureNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DirectoryExposureAnalysis analysis)
    {
        var subjCandidate = analysis.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"Directory Listing Report — {subj}";
        var subtitle = "Directory Exposure Assessment";
        var category = "Web Security";
        var keywords = $"directory listing, web, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Web servers may expose sensitive files when directory browsing is enabled.";
        var why = "Disabling directory listing reduces information disclosure and mitigates abuse.";

        var hi = new List<string>();
        var det = new List<string>();
        if (analysis.ExposedPaths != null && analysis.ExposedPaths.Count > 0)
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
        var negatives = new List<string>();
        var remediations = new List<string>();
        try
        {
            var groups = RecommendationEngine.GroupByCode(analysis.Assessments ?? new List<Assessment>());
            foreach (var g in groups)
            {
                var adviceTitle = g.Advice?.Title;
                string msg;
                if (adviceTitle != null && !string.IsNullOrWhiteSpace(adviceTitle))
                {
                    msg = adviceTitle;
                }
                else
                {
                    msg = g.Instances.FirstOrDefault()?.Message ?? g.Code;
                }
                if (g.MaxSeverity == AssessmentSeverity.Info)
                {
                    positives.Add(msg);
                }
                else
                {
                    negatives.Add(msg);
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
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
