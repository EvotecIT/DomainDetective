using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides message header narrative functionality.</summary>
public static class MessageHeaderNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(MessageHeaderAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var title = "Email Message Headers";
        var subtitle = "Header Analysis";
        var category = "Email";
        var keywords = "email,headers,DomainDetective";
        var creator = "DomainDetective";
        var intro = "Parses raw email headers to reveal routing details and authentication results.";
        var why = "Inspecting message headers helps verify sender authenticity and diagnose delivery delays.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || string.IsNullOrWhiteSpace(analysis.RawHeaders))
        {
            hi.Add("No message headers supplied.");
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
                References = DefaultRefs()
            };
        }

        if (!string.IsNullOrWhiteSpace(analysis.From) && !string.IsNullOrWhiteSpace(analysis.To))
        {
            hi.Add($"From {analysis.From} to {analysis.To}.");
        }
        if (!string.IsNullOrWhiteSpace(analysis.Subject))
        {
            hi.Add($"Subject: {analysis.Subject}.");
        }
        if (analysis.TotalTransitTime.HasValue)
        {
            hi.Add($"Total transit time {analysis.TotalTransitTime.Value.TotalMinutes:F0} minute(s).");
        }

        if (!string.IsNullOrWhiteSpace(analysis.DkimResult))
        {
            det.Add($"DKIM result: {analysis.DkimResult}.");
        }
        if (!string.IsNullOrWhiteSpace(analysis.SpfResult))
        {
            det.Add($"SPF result: {analysis.SpfResult}.");
        }
        if (!string.IsNullOrWhiteSpace(analysis.DmarcResult))
        {
            det.Add($"DMARC result: {analysis.DmarcResult}.");
        }
        if (!string.IsNullOrWhiteSpace(analysis.ArcResult))
        {
            det.Add($"ARC result: {analysis.ArcResult}.");
        }

        if (analysis.ReceivedHops.Count > 0)
        {
            det.Add($"Received hops: {analysis.ReceivedHops.Count}.");
            foreach (var hop in analysis.ReceivedHops)
            {
                var line = $"{hop.FromHost} → {hop.ByHost}";
                if (hop.HopDelay.HasValue)
                {
                    line += $" in {hop.HopDelay.Value.TotalMinutes:F0} minute(s)";
                }
                det.Add(line + ".");
            }
        }

        try
        {
            if (assessments != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
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
            References = DefaultRefs(),
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc5322",
        "https://www.rfc-editor.org/rfc/rfc7601"
    };
}
