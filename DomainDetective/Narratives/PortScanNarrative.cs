using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class PortScanNarrative
{
    public sealed class Sections : NarrativeSections { }

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

        var open = analysis.Results
            .Where(kv => kv.Value.TcpOpen || kv.Value.UdpOpen)
            .OrderBy(kv => kv.Key)
            .ToList();

        if (open.Count == 0)
        {
            hi.Add("No open ports detected.");
        }
        else
        {
            foreach (var kv in open)
            {
                var r = kv.Value;
                var proto = r.TcpOpen ? "TCP" : "UDP";
                var banner = string.IsNullOrWhiteSpace(r.Banner) ? string.Empty : $" - {r.Banner.Trim()}";
                hi.Add($"Port {kv.Key} {proto} open{banner}");
            }
        }

        foreach (var kv in analysis.Results.OrderBy(kv => kv.Key))
        {
            var r = kv.Value;
            var status = r.TcpOpen || r.UdpOpen ? "open" : "closed";
            var banner = string.IsNullOrWhiteSpace(r.Banner) ? string.Empty : $" ({r.Banner.Trim()})";
            det.Add($"Port {kv.Key} {status}{banner}");
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
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://nmap.org/book/man-port-scanning-basics.html"
    };
}
