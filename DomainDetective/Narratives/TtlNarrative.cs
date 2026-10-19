using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides ttl narrative functionality.</summary>
public static class TtlNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(DnsTtlAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
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

        var title = $"TTL Report — {subject}";
        var subtitle = "DNS TTL Assessment";
        var category = "DNS Hygiene";
        var keywords = $"TTL, DNS, caching, propagation, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "DNS Time To Live (TTL) values control how long resolvers cache records. TTLs that are too low can increase query load and latency, while TTLs that are too high can slow down propagation when changes are needed.";
        var why = "Well-chosen TTLs balance stability and agility. Consistent TTLs across authoritative name servers reduce inconsistent caching behavior and help avoid confusing, intermittent results.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Title = title,
                Subtitle = subtitle,
                Category = category,
                Keywords = keywords,
                Creator = creator,
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No TTL data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        static string MinMax(IReadOnlyList<int> values)
        {
            if (values == null || values.Count == 0)
            {
                return "-";
            }
            var nonZero = values.Where(v => v > 0).ToList();
            if (nonZero.Count == 0)
            {
                return "0";
            }
            if (nonZero.Count == 1)
            {
                return nonZero[0].ToString();
            }
            return $"{nonZero.Min()}/{nonZero.Max()}";
        }

        hi.Add($"DNSSEC signed: {(analysis.DnsSecSigned ? "Yes" : "No")}.");
        if (analysis.SoaTtl > 0)
        {
            hi.Add($"SOA TTL: {analysis.SoaTtl}s.");
        }
        hi.Add($"A TTL (min/max): {MinMax(analysis.ATtls)}.");
        hi.Add($"AAAA TTL (min/max): {MinMax(analysis.AaaaTtls)}.");
        hi.Add($"MX TTL (min/max): {MinMax(analysis.MxTtls)}.");
        hi.Add($"NS TTL (min/max): {MinMax(analysis.NsTtls)}.");

        if (analysis.UniformityIncomplete) {
            hi.Add("Authoritative TTL uniformity could not be fully verified; some TTL evidence is missing.");
        } else {
            void AddUniformity(string label, Dictionary<string, int?> values, bool uniform) {
                if (values.Count == 0) { hi.Add($"{label} TTL uniformity was not evaluated."); }
                else if (values.Values.Any(value => !value.HasValue)) { hi.Add($"Some authoritative replies contain no {label} TTL to compare."); }
                else { hi.Add(uniform ? $"{label} TTL uniform across name servers." : $"{label} TTL varies across name servers."); }
            }
            AddUniformity("A", analysis.ServerTtlA, analysis.AUniformAcrossServers);
            AddUniformity("AAAA", analysis.ServerTtlAaaa, analysis.AaaaUniformAcrossServers);
            AddUniformity("NS", analysis.ServerTtlNs, analysis.NsUniformAcrossServers);
            AddUniformity("CNAME", analysis.ServerTtlCname, analysis.CnameUniformAcrossServers);
        }

        try
        {
            var assess = assessments ?? analysis.Assessments;
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assess);
        }
        catch
        {
        }

        var refs = DefaultRefs();

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

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc1035"
    };
}

