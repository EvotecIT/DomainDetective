using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class TtlNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DnsTtlAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"DNS TTL Report — {subj}";
        var subtitle = "DNS TTL Assessment";
        var category = "DNS";
        var keywords = $"DNS, TTL, caching, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Time to Live (TTL) values control how long DNS data stays cached before revalidation.";
        var why = "Appropriate TTLs balance caching efficiency with agility for updates; inconsistent values can cause cache churn or stale records.";

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
                Highlights = new List<string> { "No TTL data available." },
                Details = det,
                References = new List<string> { "https://www.rfc-editor.org/rfc/rfc1035" }
            };
        }

        hi.Add($"SOA TTL: {analysis.SoaTtl}s.");
        if (analysis.ATtls?.Count > 0)
        {
            hi.Add($"A TTLs min/max {analysis.ATtls.Min()}/{analysis.ATtls.Max()}s.");
        }
        if (analysis.AaaaTtls?.Count > 0)
        {
            hi.Add($"AAAA TTLs min/max {analysis.AaaaTtls.Min()}/{analysis.AaaaTtls.Max()}s.");
        }
        if (analysis.AUniformAcrossServers)
        {
            hi.Add("A TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlA.Count > 0)
        {
            hi.Add("A TTLs vary across name servers.");
        }
        if (analysis.AaaaUniformAcrossServers)
        {
            hi.Add("AAAA TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlAaaa.Count > 0)
        {
            hi.Add("AAAA TTLs vary across name servers.");
        }
        if (analysis.NsUniformAcrossServers)
        {
            hi.Add("NS TTLs uniform across name servers.");
        }
        else if (analysis.ServerTtlNs.Count > 0)
        {
            hi.Add("NS TTLs vary across name servers.");
        }

        if (analysis.Warnings != null && analysis.Warnings.Count > 0)
        {
            hi.AddRange(analysis.Warnings);
        }
        else
        {
            hi.Add("TTL values appear balanced for caching and agility.");
        }

        if (analysis.ATtls?.Count > 0)
        {
            det.Add($"A: {string.Join(", ", analysis.ATtls)}");
        }
        if (analysis.AaaaTtls?.Count > 0)
        {
            det.Add($"AAAA: {string.Join(", ", analysis.AaaaTtls)}");
        }
        if (analysis.MxTtls?.Count > 0)
        {
            det.Add($"MX: {string.Join(", ", analysis.MxTtls)}");
        }
        if (analysis.NsTtls?.Count > 0)
        {
            det.Add($"NS: {string.Join(", ", analysis.NsTtls)}");
        }

        var refs = new List<string> { "https://www.rfc-editor.org/rfc/rfc1035" };

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                AssessmentSplit.SplitTitles(ass, out positives, out remediations);
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
            Positives = positives,
            Remediations = remediations
        };
    }
}
