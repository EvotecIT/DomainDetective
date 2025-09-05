using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class MailLatencyNarrative {
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(MailLatencyAnalysis analysis, IEnumerable<Assessment>? assessments = null) {
        var subj = analysis?.ServerResults.Keys.FirstOrDefault() ?? "(server)";
        var title = $"Mail Latency Report — {subj}";
        var subtitle = "Mail Latency Assessment";
        var category = "Email Infrastructure";
        var keywords = $"SMTP, latency, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Mail server responsiveness impacts delivery reliability and client performance.";
        var why = "Low connection and banner latencies improve throughput and user experience.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.ServerResults.Count == 0) {
            hi.Add("No mail latency data available.");
        } else {
            foreach (var kv in analysis.ServerResults) {
                var r = kv.Value;
                hi.Add($"{kv.Key} connect {r.ConnectTime.TotalMilliseconds:F0} ms, banner {r.BannerTime.TotalMilliseconds:F0} ms");
            }
        }

        try {
            if (assessments != null) {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
            }
        } catch { }

        var refs = new List<string> { "https://www.rfc-editor.org/rfc/rfc5321" };

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
}
