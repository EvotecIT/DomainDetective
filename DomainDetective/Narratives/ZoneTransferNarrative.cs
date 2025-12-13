using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class ZoneTransferNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ZoneTransferAnalysis analysis, IEnumerable<Assessment>? assessments = null, InternalLogger? logger = null)
    {
        var s = analysis?.Subject;
        var subject = string.IsNullOrWhiteSpace(s) ? "(domain)" : s;
        var title = $"Zone Transfer Report — {subject}";
        var subtitle = "AXFR Exposure Assessment";
        var category = "DNS Security";
        var keywords = $"AXFR, zone transfer, DNS, security, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "Zone transfer (AXFR) testing checks whether name servers permit unauthenticated transfers.";
        var why = "Open zone transfers expose complete DNS zone data, easing reconnaissance.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        var results = analysis?.ServerResults ?? new Dictionary<string, bool>();
        var total = results.Count;
        var opens = results.Count(kv => kv.Value);

        if (total > 0)
            hi.Add($"Servers tested: {total}");
        if (opens > 0)
            hi.Add($"{opens} server(s) allowed AXFR.");
        else if (total > 0)
            hi.Add("All tested servers refused AXFR.");

        foreach (var kv in results)
        {
            det.Add($"{kv.Key}: {(kv.Value ? "allowed" : "refused")}");
        }

        var refs = new List<string>
        {
            "https://www.rfc-editor.org/rfc/rfc5936"
        };

        try
        {
            var assess = assessments ?? analysis?.Assessments ?? new List<Assessment>();
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assess);
        }
        catch (Exception ex)
        {
            logger?.WriteWarning($"Failed to split assessments: {ex.Message}");
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
}
