using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides spf flattened narrative functionality.</summary>
public static class SpfFlattenedNarrative {
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(SpfAnalysis? spf, IEnumerable<Assessment>? assessments = null) {
        var subj = string.IsNullOrWhiteSpace(spf?.Subject) ? "(domain)" : spf!.Subject!;
        var title = $"SPF Flattened Report — {subj}";
        var subtitle = "SPF Flattened IP Assessment";
        var category = "Email Security";
        var keywords = $"SPF, flattening, email, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Flattening expands SPF mechanisms into direct IP addresses, avoiding runtime DNS lookups.";
        var why = "Minimizing DNS lookups keeps SPF under the 10-lookup limit and produces a deterministic policy.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (spf?.FlattenedIpAnalysis?.UniqueIps?.Count > 0) {
            hi.Add($"Unique IPs: {spf.FlattenedIpAnalysis.UniqueIps.Count}.");
            if (spf.FlattenedIpAnalysis.DuplicateIps.Count > 0) {
                det.Add($"Duplicate IPs: {string.Join(", ", spf.FlattenedIpAnalysis.DuplicateIps)}");
            } else {
                det.Add("No duplicate IPs detected; flattened set is minimal.");
            }
        } else {
            hi.Add("No IPs resolved from SPF.");
        }

        hi.Add($"DNS lookups used: {spf?.DnsLookupsCount ?? 0}/10{(spf?.ExceedsDnsLookups == true ? " (exceeds limit)" : " (within limit)")}");

        var refs = new List<string> { "https://datatracker.ietf.org/doc/html/rfc7208" };

        try {
            if (assessments != null) {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
            }
        } catch { }

        return new Sections {
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
            Negatives = negatives,
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
