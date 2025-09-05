using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>
/// Generates narrative sections summarizing port availability results.
/// </summary>
public static class PortAvailabilityNarrative
{
    /// <summary>
    /// Container for generated narrative sections.
    /// </summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>
    /// Builds narrative sections from a <see cref="PortAvailabilityAnalysis"/>.
    /// </summary>
    /// <param name="analysis">The port availability analysis to summarize.</param>
    /// <param name="assessments">Optional assessments to include.</param>
    /// <returns>The narrative sections describing the analysis.</returns>
    public static Sections Build(PortAvailabilityAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var intro = "Port availability checks verify that expected services accept connections.";
        var why = "Ensuring required ports respond confirms service uptime and firewall configuration.";
        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        if (analysis == null || analysis.ServerResults.Count == 0)
        {
            return new Sections
            {
                Introduction = intro,
                WhyItMatters = why,
                Highlights = new List<string> { "No port availability data." },
                Details = det,
                References = DefaultRefs()
            };
        }

        var sorted = analysis.ServerResults.OrderBy(kv => kv.Key).ToList();
        foreach (var kv in sorted)
        {
            var res = kv.Value;
            var status = res.Success ? "reachable" : "unreachable";
            det.Add($"{kv.Key} {status}");
            if (res.Success)
            {
                hi.Add($"{kv.Key} reachable");
            }
        }

        if (hi.Count == 0)
        {
            hi.Add("No ports were reachable.");
        }

        try
        {
            var ass = assessments ?? analysis.Assessments;
            if (ass != null)
            {
                AssessmentSplit.SplitTitles(ass, out positives, out remediations);
            }
        }
        catch { }

        return new Sections
        {
            Title = "Port Availability Check",
            Subtitle = "Port Availability Assessment",
            Category = "Network Availability",
            Keywords = "Port availability, services, DomainDetective",
            Creator = "DomainDetective",
            Introduction = intro,
            WhyItMatters = why,
            Highlights = hi,
            Details = det,
            References = DefaultRefs(),
            Positives = positives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc793"
    };
}
