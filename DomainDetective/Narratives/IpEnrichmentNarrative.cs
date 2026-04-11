using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides ip enrichment narrative functionality.</summary>
public static class IpEnrichmentNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(IpEnrichmentAnalysis? analysis)
    {
        var subj = !string.IsNullOrWhiteSpace(analysis?.Subject) ? analysis!.Subject! : "(domain)";
        var title = $"IP Enrichment — {subj}";
        var subtitle = "IP Footprint (rDNS, ASN, Geo)";
        var category = "Infrastructure";
        var keywords = $"IP, ASN, RDAP, reverse DNS, geo, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "IP enrichment summarizes where a domain is hosted by enumerating discovered IPs and enriching them with reverse DNS and registry metadata.";
        var why = "Understanding ASN and geographic footprint helps spot unexpected hosting changes, shared infrastructure risks, and routing/ownership anomalies.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis != null)
        {
            hi.Add($"Unique IPs enriched: {analysis.UniqueIpCount}.");
            hi.Add($"Rows (including per-source duplicates): {analysis.RowCount}.");
            hi.Add($"ASN diversity: {analysis.DistinctAsnCount}.");
            hi.Add($"Country diversity: {analysis.DistinctCountryCount}.");
            if (analysis.ResultsCapped)
            {
                hi.Add("Results were capped for performance.");
            }

            if (analysis.AsnCounts != null && analysis.AsnCounts.Count > 0)
            {
                var top = analysis.AsnCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => $"AS{kv.Key} ({kv.Value})");
                det.Add("Top ASNs: " + string.Join(", ", top));
            }
            if (analysis.CountryCounts != null && analysis.CountryCounts.Count > 0)
            {
                var top = analysis.CountryCounts.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key).Take(5).Select(kv => $"{kv.Key} ({kv.Value})");
                det.Add("Top countries: " + string.Join(", ", top));
            }

            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>());
        }
        else
        {
            hi.Add("No IP enrichment data available.");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc1035",
            "https://datatracker.ietf.org/doc/html/rfc7482"
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
            Negatives = negatives,
            Remediations = remediations.Distinct().ToList()
        };
    }
}

