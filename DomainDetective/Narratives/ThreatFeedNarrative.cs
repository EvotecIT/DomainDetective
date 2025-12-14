using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class ThreatFeedNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ThreatFeedAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjCandidate = analysis?.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(IP)";
        }
        var title = $"Threat Feed Report — {subj}";
        var subtitle = "Threat Feed";
        var category = "Threat Intelligence";
        var keywords = $"threat feed, reputation, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "External threat feeds track malicious IP reputation across services.";
        var why = "Regular checks help detect compromised or abusive hosts early.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No threat feed data available." },
                Details = det,
                References = new List<string> { "https://www.virustotal.com/", "https://www.abuseipdb.com/" }
            };
        }

        foreach (var f in analysis.Listings)
        {
            det.Add($"{Label(f.Source)}: {(f.IsListed ? "listed" : "not listed")}");
            if (f.IsListed)
            {
                hi.Add($"{Label(f.Source)} reports malicious activity.");
            }
        }

        if (hi.Count == 0)
        {
            hi.Add("No threat feed listings detected.");
        }

        if (!string.IsNullOrWhiteSpace(analysis.FailureReason))
        {
            det.Add($"Failure reason: {analysis.FailureReason}");
        }

        var refs = new List<string>
        {
            "https://www.virustotal.com/",
            "https://www.abuseipdb.com/"
        };

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(ass);
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
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static string Label(ThreatIntelSource source)
    {
        return source switch
        {
            ThreatIntelSource.VirusTotal => "VirusTotal",
            ThreatIntelSource.AbuseIpDb => "AbuseIPDB",
            _ => source.ToString()
        };
    }
}
