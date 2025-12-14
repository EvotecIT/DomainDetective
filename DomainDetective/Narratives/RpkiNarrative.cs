using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class RpkiNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(RPKIAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjectCandidate = analysis?.Subject;
        string subject;
        if (subjectCandidate != null && !string.IsNullOrWhiteSpace(subjectCandidate))
        {
            subject = subjectCandidate;
        }
        else
        {
            subject = "(domain)";
        }
        var title = $"RPKI Report — {subject}";
        var subtitle = "RPKI Assessment";
        var category = "Infrastructure";
        var keywords = $"RPKI, BGP, routing, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "Resource Public Key Infrastructure (RPKI) validates that IP prefixes are authorised for an autonomous system.";
        var why = "Valid Route Origin Authorisations (ROAs) help prevent BGP hijacking by ensuring only authorised ASNs announce prefixes.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.Results.Count == 0)
        {
            hi.Add("No RPKI data available.");
        }
        else
        {
            foreach (var r in analysis.Results)
            {
                var status = r.Valid ? "valid" : "invalid";
                hi.Add($"{r.IpAddress} ⇒ {r.Prefix} (AS{r.Asn}) {status}.");
                det.Add($"IP {r.IpAddress} prefix {r.Prefix} ASN {r.Asn} valid={r.Valid}");
            }
            var assess = assessments ?? analysis.Assessments ?? new List<Assessment>();
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assess);
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc6483",
            "https://rpki.readthedocs.io/"
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
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }
}

