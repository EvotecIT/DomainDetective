using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class OpenRelayNarrative
{
    public sealed class Sections
    {
        public string Title { get; init; } = string.Empty;
        public string Subtitle { get; init; } = string.Empty;
        public string Category { get; init; } = string.Empty;
        public string Keywords { get; init; } = string.Empty;
        public string Creator { get; init; } = string.Empty;
        public string Introduction { get; init; } = string.Empty;
        public string WhyItMatters { get; init; } = string.Empty;
        public List<string> Highlights { get; init; } = new();
        public List<string> Details { get; init; } = new();
        public List<string> References { get; init; } = new();
        public List<string> Positives { get; init; } = new();
        public List<string> Remediations { get; init; } = new();
    }

    public static Sections Build(OpenRelayAnalysis analysis)
    {
        var title = "Open Relay Report";
        var subtitle = "SMTP Relay Assessment";
        var category = "Email Security";
        var keywords = "SMTP relay, email, security, DomainDetective";
        var creator = "DomainDetective";
        var intro = "Open relay testing probes SMTP servers to see if they permit unauthenticated third-party mail.";
        var why = "Open relays are abused to send spam and malware. Denying unauthenticated relay protects infrastructure and reputation.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        var results = analysis?.ServerResults ?? new Dictionary<string, OpenRelayAnalysis.OpenRelayResult>();
        var total = results.Count;
        var allows = results.Count(r => r.Value?.Status == OpenRelayStatus.AllowsRelay);
        var denied = results.Count(r => r.Value?.Status == OpenRelayStatus.Denied);
        var failed = results.Count(r => r.Value?.Status == OpenRelayStatus.ConnectionFailed);

        if (total > 0)
            hi.Add($"Servers tested: {total}");
        if (allows > 0)
            hi.Add($"{allows} server(s) allowed unauthenticated relay.");
        else
            hi.Add("No servers allowed unauthenticated relay.");

        if (denied > 0)
            hi.Add($"{denied} server(s) denied relay.");
        if (failed > 0)
            hi.Add($"{failed} server(s) failed to connect.");

        foreach (var kv in results)
        {
            det.Add($"{kv.Key}: {kv.Value.Status}");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc5321"
        };

        try
        {
            AssessmentSplit.SplitTitles(analysis?.Assessments ?? new List<Assessment>(), out positives, out remediations);
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
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }
}
