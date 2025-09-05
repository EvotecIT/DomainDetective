using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class ApexAddressNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ApexAddressAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject;
        var title = $"Apex Address Report — {subj}";
        var subtitle = "Apex Address Assessment";
        var category = "DNS Infrastructure";
        var keywords = $"Apex address, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Apex A and AAAA records provide fallback routing when MX records are absent.";
        var why = "Public, diverse apex addresses with valid reverse DNS improve resilience and deliverability.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        hi.Add($"A records: {analysis.IPv4Count}");
        hi.Add($"AAAA records: {analysis.IPv6Count}");
        hi.Add($"IPv4 subnets: {analysis.DistinctSubnetCountV4}");
        hi.Add($"IPv6 subnets: {analysis.DistinctSubnetCountV6}");
        hi.Add(analysis.AllFcrDnsValid
            ? "Reverse DNS is forward-confirmed for all addresses."
            : analysis.AnyPtrPresent ? "Some addresses have reverse DNS." : "No reverse DNS for addresses.");

        foreach (var kv in analysis.PtrByIp)
        {
            var ptrs = kv.Value != null && kv.Value.Count > 0 ? string.Join(", ", kv.Value) : "(no PTR)";
            det.Add($"{kv.Key} -> {ptrs}");
        }

        var refs = analysis.RfcReferences?.Select(r => r.Url).ToList() ?? new List<string>();

        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
            }
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
}
