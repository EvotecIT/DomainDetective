using System.Collections.Generic;

namespace DomainDetective.Narratives;

public static class NtpNarrative {
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(NtpAnalysis analysis) {
        var title = "NTP Report";
        var subtitle = "Network Time Protocol Assessment";
        var category = "Infrastructure";
        var keywords = "ntp, time, DomainDetective";
        var creator = "DomainDetective";
        var intro = "NTP synchronizes clocks across systems.";
        var why = "Accurate time underpins authentication, logging and security.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        var results = analysis?.ServerResults ?? new Dictionary<string, NtpAnalysis.NtpResult>();
        if (results.Count == 0) {
            hi.Add("No NTP data available.");
        } else {
            foreach (var kv in results) {
                var r = kv.Value;
                if (r.Success) {
                    var line = $"{kv.Key} offset {r.Offset.TotalMilliseconds:F0} ms; stratum {r.Stratum}";
                    hi.Add(line);
                    det.Add(line);
                } else {
                    hi.Add($"{kv.Key} no response");
                }
            }
        }

        AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>(), out positives, out remediations);

        var refs = new List<string> {
            "https://datatracker.ietf.org/doc/html/rfc5905"
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
            Remediations = remediations
        };
    }
}

