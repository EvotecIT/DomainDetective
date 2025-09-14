using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class DnsHealthNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(DnsHealthAnalysis analysis)
    {
        var subject = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"DNS Health Report — {subject}";
        var subtitle = "DNS Health Assessment";
        var category = "DNS Infrastructure";
        var keywords = $"DNS, infrastructure, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "Evaluates authoritative nameserver consistency and responsiveness.";
        var why = "Consistent, responsive nameservers ensure reliable DNS resolution.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis != null)
        {
            hi.Add(analysis.SoaSerialConsistent
                ? "SOA serial numbers match across authoritative servers."
                : "SOA serial numbers differ across authoritative servers.");
            hi.Add(analysis.ApexAddressesConsistent
                ? "A/AAAA records for zone apex are consistent across servers."
                : "A/AAAA records for zone apex differ among servers.");
            hi.Add(analysis.ServersResponsive
                ? "All authoritative servers responded to queries."
                : "Some authoritative servers did not respond.");

            if (analysis.NameServers?.Count > 0)
            {
                det.Add($"NS set: {string.Join(", ", analysis.NameServers)}");
            }
            foreach (var kv in analysis.SoaSerialByServer)
            {
                det.Add($"SOA serial from {kv.Key}: {kv.Value}");
            }
            foreach (var kv in analysis.ApexAddressesByServer)
            {
                det.Add($"Apex answers from {kv.Key}: {string.Join(", ", kv.Value)}");
            }

            AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);
        }
        else
        {
            hi.Add("No DNS health data available.");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc1034",
            "https://datatracker.ietf.org/doc/html/rfc1035"
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
