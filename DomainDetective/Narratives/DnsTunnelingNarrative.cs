using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides dns tunneling narrative functionality.</summary>
public static class DnsTunnelingNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(DnsTunnelingAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjCandidate = analysis?.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(domain)";
        }
        var title = $"DNS Tunneling Report — {subj}";
        var subtitle = "DNS tunneling analysis";
        var category = "Threat Intel";
        var keywords = $"DNS, tunneling, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "DNS tunneling can covertly transfer data or commands within DNS queries.";
        var why = "Detecting abnormal query labels and burst rates helps uncover misuse of DNS for exfiltration or C2.";

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
                Highlights = new List<string> { "No DNS tunneling data available." },
                Details = det,
                References = new List<string> { "https://en.wikipedia.org/wiki/DNS_tunneling" }
            };
        }

        if (analysis.Alerts.Count == 0)
        {
            hi.Add("No tunneling indicators detected.");
        }
        else
        {
            hi.Add($"{analysis.Alerts.Count} potential tunneling indicators detected.");
            foreach (var a in analysis.Alerts)
            {
                det.Add($"{a.Domain}: {a.Reason}");
            }
        }

        hi.Add($"Frequency threshold: {analysis.FrequencyThreshold} queries/{analysis.FrequencyInterval.TotalSeconds:0.##}s");

        var refs = new List<string> { "https://en.wikipedia.org/wiki/DNS_tunneling" };

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(ass);
            }
        }
        catch (Exception ex)
        {
            // Log the exception or handle specific expected exceptions
            // For now, continue with empty lists which is the current behavior
            _ = ex;
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
}
