using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class ReverseDnsNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ReverseDnsAnalysis rdns)
    {
        var subj = string.IsNullOrWhiteSpace(rdns.Subject) ? "(domain)" : rdns.Subject;
        var title = $"Reverse DNS Report — {subj}";
        var subtitle = "Reverse DNS Assessment";
        var category = "DNS Infrastructure";
        var keywords = $"PTR, reverse DNS, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Reverse DNS maps IP addresses to hostnames.";
        var why = "Proper reverse DNS aids in email delivery and reputation checks.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        var rawResults = rdns.Results;
        var results = rawResults ?? new List<ReverseDnsAnalysis.ReverseDnsResult>();
        var total = results.Count;
        var withPtr = results.Count(r => !string.IsNullOrWhiteSpace(r.PtrRecord));
        var allValid = rawResults != null && results.All(r => r.IsValid);
        var allFcr = rawResults != null && results.All(r => r.FcrDnsValid);
        hi.Add($"PTR records found: {withPtr}/{total}.");
        hi.Add(allValid ? "PTR names align with MX hosts." : "PTR names do not align with all MX hosts.");
        hi.Add(allFcr ?
            "PTR hostnames resolve back to their IP addresses." :
            "Some PTR hostnames fail to resolve back to their IP addresses.");

        foreach (var r in results)
        {
            det.Add(string.IsNullOrWhiteSpace(r.PtrRecord)
                ? $"{r.IpAddress} has no PTR record."
                : $"{r.IpAddress} -> {r.PtrRecord}{(r.IsValid ? string.Empty : $" (expected {r.ExpectedHost})")}");
        }

        var refs = new List<string> { "https://www.rfc-editor.org/rfc/rfc1912#section-2.1" };

        try
        {
            var assessments = (IEnumerable<Assessment>)(rdns.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                string msg;
                var adviceTitle = g.Advice?.Title;
                if (adviceTitle == null || string.IsNullOrWhiteSpace(adviceTitle)) {
                    msg = g.Instances.FirstOrDefault()?.Message ?? g.Code;
                } else {
                    msg = adviceTitle;
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
        catch (Exception)
        {
            // Intentionally ignore recommendation processing errors to keep narrative generation resilient.
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
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
