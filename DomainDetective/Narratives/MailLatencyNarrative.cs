using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class MailLatencyNarrative {
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(MailLatencyAnalysis analysis) {
        var subj = "(servers)";
        if (analysis?.ServerResults != null && analysis.ServerResults.Count == 1) {
            foreach (var key in analysis.ServerResults.Keys) { subj = key; break; }
        }
        var title = $"Mail Latency Report — {subj}";
        var subtitle = "SMTP Latency Assessment";
        var category = "Email Performance";
        var keywords = $"mail latency, smtp, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Mail latency measures time to connect to SMTP servers and receive their greeting banner.";
        var why = "Responsive servers improve mail delivery speed and troubleshooting.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        var results = analysis?.ServerResults ?? new Dictionary<string, MailLatencyAnalysis.LatencyResult>();
        if (results.Count == 0) {
            hi.Add("No mail latency data available.");
        } else {
            foreach (var kv in results) {
                var r = kv.Value;
                var connect = r.ConnectSuccess ? $"{(int)r.ConnectTime.TotalMilliseconds} ms" : "failed";
                var banner = r.BannerSuccess ? $"{(int)r.BannerTime.TotalMilliseconds} ms" : "failed";
                var line = $"{kv.Key} connect {connect}; banner {banner}";
                hi.Add(line);
                det.Add(line);
            }
        }

        AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);

        var refs = new List<string> {
            "https://www.rfc-editor.org/rfc/rfc5321"
        };

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
            Negatives = negatives,
            Remediations = remediations
        };
    }
}
