using System;
using System.Collections.Generic;

namespace DomainDetective.Narratives;

/// <summary>Provides ntp narrative functionality.</summary>
public static class NtpNarrative {
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
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
        var negatives = new List<string>();
        var remediations = new List<string>();

        var results = analysis?.ServerResults ?? new Dictionary<string, NtpAnalysis.NtpResult>();
        if (results.Count == 0) {
            hi.Add("No NTP data available.");
        } else {
            foreach (var kv in results) {
                var r = kv.Value;
                if (r.Success) {
                    var line = $"{kv.Key} offset {FormatOffset(r.Offset)}; stratum {r.Stratum}";
                    hi.Add(line);
                    det.Add(line);
                } else {
                    hi.Add($"{kv.Key} no response");
                }
            }
        }

        (positives, negatives, remediations) = AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>());

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
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static string FormatOffset(TimeSpan offset) {
        var ms = offset.TotalMilliseconds;
        var absMs = Math.Abs(ms);
        if (absMs < 1000) {
            return $"{ms:F0} ms";
        }

        var absSec = Math.Abs(offset.TotalSeconds);
        if (absSec < 60) {
            return $"{offset.TotalSeconds:F2} s";
        }

        var absMin = Math.Abs(offset.TotalMinutes);
        if (absMin < 60) {
            return $"{offset.TotalMinutes:F2} m";
        }

        return $"{offset.TotalHours:F2} h";
    }
}

