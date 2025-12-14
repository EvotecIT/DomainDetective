using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class TyposquattingNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(TyposquattingAnalysis analysis)
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
        var title = $"Typosquatting Report — {subj}";
        var subtitle = "Typosquatting Assessment";
        var category = "Brand Protection";
        var keywords = $"typosquatting, brand, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Typosquatting involves registering look-alike domains to deceive users or capture traffic.";
        var why = "Monitoring and defensively registering variants reduces impersonation risk.";

        var hi = new List<string>();
        var det = new List<string>();
        var active = analysis.ActiveDomains ?? new List<string>();
        if (active.Count > 0)
        {
            hi.Add($"Active typosquat domains: {string.Join(", ", active)}");
            det.AddRange(active.Select(d => $"Active: {d}"));
        }
        else
        {
            hi.Add("No active typosquat domains detected.");
        }

        var available = (analysis.Variants ?? new List<string>())
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
