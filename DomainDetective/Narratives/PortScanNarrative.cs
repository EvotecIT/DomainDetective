using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>
/// Generates narrative sections summarizing port scan results.
/// </summary>
public static class PortScanNarrative
{
    /// <summary>
    /// Container for generated narrative sections.
    /// </summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>
    /// Builds narrative sections from a <see cref="PortScanAnalysis"/>.
    /// </summary>
    /// <param name="analysis">The port scan analysis to summarize.</param>
    /// <param name="assessments">Optional assessments to include.</param>
    /// <returns>The narrative sections describing the analysis.</returns>
    public static Sections Build(PortScanAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(host)" : analysis.Subject!;
        var title = $"Port Scan Report — {subj}";
        var subtitle = "Port Scan Assessment";
        var category = "Network Security";
        var keywords = $"Port scan, services, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Port scanning identifies reachable services and their banners.";
        var why = "Knowing exposed services helps reduce attack surface and verify expected configurations.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.Results.Count == 0)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No port scan data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        var sorted = analysis.Results.OrderBy(kv => kv.Key).ToList();
        var openCount = 0;

        foreach (var kv in sorted)
        {
            var r = kv.Value;
            var bannerText = string.IsNullOrWhiteSpace(r.Banner) ? string.Empty : r.Banner.Trim();
            var status = r.TcpOpen || r.UdpOpen;

            if (status)
            {
                openCount++;
                var proto = r.TcpOpen ? "TCP" : "UDP";
                var bannerHi = string.IsNullOrEmpty(bannerText) ? string.Empty : $" - {bannerText}";
                hi.Add($"Port {kv.Key} {proto} open{bannerHi}");
            }

            var bannerDet = string.IsNullOrEmpty(bannerText) ? string.Empty : $" ({bannerText})";
            var state = status ? "open" : "closed";
            det.Add($"Port {kv.Key} {state}{bannerDet}");
        }

        if (openCount == 0)
        {
            hi.Add("No open ports detected.");
        }

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(ass);
            }
        }
        catch { }

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

    /// <summary>
    /// Default reference links explaining port scanning fundamentals.
    /// </summary>
    private static List<string> DefaultRefs() => new()
    {
        "https://nmap.org/book/man-port-scanning-basics.html"
    };
}
