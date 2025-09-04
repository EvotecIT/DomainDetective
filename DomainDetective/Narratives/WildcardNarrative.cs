using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class WildcardNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(WildcardDnsAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var title = "Wildcard DNS Report";
        var subtitle = "Wildcard DNS Assessment";
        var category = "DNS Infrastructure";
        var keywords = "wildcard, DNS, DomainDetective";
        var creator = "DomainDetective";
        var intro = "Wildcard DNS responds to non-existent subdomains with synthesized records.";
        var why = "Unintended wildcard records can hide configuration errors and enable phishing or takeover scenarios.";

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
                Highlights = new List<string> { "No wildcard data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.CatchAll ? "Wildcard DNS detected." : "No wildcard DNS detected.");
        if (analysis.TestedNames.Count > 0)
        {
            hi.Add($"{analysis.TestedNames.Count} random names tested.");
            hi.Add($"{analysis.ResolvedNames.Count} resolved; {analysis.ResolvedAddresses.Count} unique address(es).");
        }

        det.Add(analysis.CatchAll
            ? "Random subdomains resolved to existing addresses."
            : "Random subdomains returned NXDOMAIN.");
        det.Add(analysis.SoaExists ? "SOA record present." : "SOA record missing.");
        det.Add(analysis.NsExists ? "NS records present." : "NS records missing.");

        var refs = DefaultRefs();

        try
        {
            var assess = assessments ?? analysis.Assessments;
            AssessmentSplit.SplitTitles(assess, out positives, out remediations);
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
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc4592"
    };
}
