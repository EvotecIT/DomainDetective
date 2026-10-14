using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides dns health narrative functionality.</summary>
public static class DnsHealthNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(DnsHealthAnalysis? analysis)
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
            hi.Add(analysis.SoaSerialConsistency switch {
                DnsHealthConsistencyStatus.Consistent => "SOA serial numbers match across authoritative servers.",
                DnsHealthConsistencyStatus.Inconsistent => "SOA serial numbers differ across observed authoritative servers.",
                _ => "Insufficient authoritative evidence to confirm SOA serial consistency."
            });
            hi.Add(analysis.ApexAddressesConsistency switch {
                DnsHealthConsistencyStatus.Consistent => "A/AAAA records for zone apex are consistent across servers.",
                DnsHealthConsistencyStatus.Inconsistent => "A/AAAA records for zone apex differ among observed servers.",
                _ => "Insufficient authoritative evidence to confirm apex A/AAAA consistency."
            });
            hi.Add(analysis.ResponsivenessSummary);

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
            foreach (var probe in analysis.ProbeResults) {
                det.Add($"{probe.ServerAddress} {probe.RecordType}: {probe.ResponseCode?.ToString() ?? (probe.Attempted ? "unanswered" : "not attempted")}; {probe.Answers.Count} records; {probe.ElapsedMilliseconds} ms{(string.IsNullOrEmpty(probe.Error) ? string.Empty : "; " + probe.Error)}");
            }
            foreach (var discovery in analysis.DiscoveryResults) {
                det.Add($"Discovery {discovery.Name} {discovery.RecordType}: {discovery.ResponseCode?.ToString() ?? "incomplete"}{(string.IsNullOrEmpty(discovery.Error) ? string.Empty : "; " + discovery.Error)}");
            }

            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>());
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
