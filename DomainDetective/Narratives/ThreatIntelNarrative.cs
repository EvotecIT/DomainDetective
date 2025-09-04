using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class ThreatIntelNarrative {
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(ThreatIntelAnalysis ti) {
        var subj = string.IsNullOrWhiteSpace(ti?.Subject) ? "(domain)" : ti.Subject;
        var title = $"Threat Intelligence Report — {subj}";
        var subtitle = "Threat Intelligence";
        var category = "Security";
        var keywords = $"threat intelligence, malware, reputation, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Threat intelligence services identify malicious domains and IPs across global feeds.";
        var why = "Monitoring these feeds helps detect compromises early and protect users.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (ti?.Listings != null) {
            foreach (var f in ti.Listings) {
                hi.Add($"{Label(f.Source)}: {(f.IsListed ? "listed" : "not listed")}");
            }
        }

        if (ti?.RiskScore != null) {
            hi.Add($"Reputation score: {ti.RiskScore}");
        }

        if (ti?.CompositeScore != null) {
            det.Add($"Composite score: {ti.CompositeScore}/100");
        }

        if (!string.IsNullOrWhiteSpace(ti?.Severity)) {
            det.Add($"Severity: {ti.Severity}");
        }

        if (ti?.Confidence != null) {
            det.Add($"Confidence: {ti.Confidence:P0}");
        }

        if (!string.IsNullOrWhiteSpace(ti?.FailureReason)) {
            det.Add($"Failure reason: {ti.FailureReason}");
        }

        var refs = new List<string> {
            "https://developers.google.com/safe-browsing/",
            "https://phishtank.com/",
            "https://www.virustotal.com/"
        };

        try {
            AssessmentSplit.SplitTitles(ti?.Assessments ?? new List<Assessment>(), out positives, out remediations);
        } catch {
        }

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
            Positives = positives,
            Remediations = remediations
        };
    }

    private static string Label(ThreatIntelSource source) {
        return source switch {
            ThreatIntelSource.GoogleSafeBrowsing => "Google Safe Browsing",
            ThreatIntelSource.PhishTank => "PhishTank",
            ThreatIntelSource.VirusTotal => "VirusTotal",
            ThreatIntelSource.UrlHaus => "URLHaus",
            ThreatIntelSource.OpenPhish => "OpenPhish",
            _ => source.ToString()
        };
    }
}
