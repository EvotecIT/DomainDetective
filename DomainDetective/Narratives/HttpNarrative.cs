using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class HttpNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(HttpAnalysis analysis)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(host)" : analysis.Subject!;
        var title = $"HTTP Report — {subj}";
        var subtitle = "HTTP Response and Header Summary";
        var category = "Web Security";
        var keywords = $"HTTP, security headers, redirects, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "HTTP responses and headers reveal security posture.";
        var why = "Redirecting to HTTPS and strong headers protect users.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis != null)
        {
            if (analysis.StatusCode.HasValue)
            {
                hi.Add($"Final status code {analysis.StatusCode}.");
            }

            if (analysis.VisitedUrls.Count > 1)
            {
                hi.Add($"Redirect chain: {string.Join(" -> ", analysis.VisitedUrls)}.");
            }

            if (analysis.SecurityHeaders.Count > 0)
            {
                hi.Add($"Security headers: {string.Join(", ", analysis.SecurityHeaders.Keys)}.");
            }

            if (analysis.MissingSecurityHeaders.Count > 0)
            {
                det.Add($"Missing headers: {string.Join(", ", analysis.MissingSecurityHeaders)}");
            }

            foreach (var url in analysis.VisitedUrls)
            {
                det.Add($"Visited {url}");
            }

            AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);
        }
        else
        {
            hi.Add("No HTTP data available.");
        }

        var refs = new List<string>
        {
            "https://developer.mozilla.org/docs/Web/HTTP/Status",
            "https://developer.mozilla.org/docs/Web/HTTP/Headers"
        };

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
            Positives = positives.Distinct().ToList(),
            Negatives = negatives.Distinct().ToList(),
            Remediations = remediations.Distinct().ToList()
        };
    }
}
