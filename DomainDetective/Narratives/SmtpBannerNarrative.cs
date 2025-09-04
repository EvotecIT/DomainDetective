using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class SmtpBannerNarrative
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

    public static Sections Build(SMTPBannerAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(host)" : analysis.Subject!;
        var title = $"SMTP Banner Report — {subj}";
        var subtitle = "SMTP Banner Assessment";
        var category = "Email Security";
        var keywords = $"SMTP, banner, email, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SMTP servers greet clients with a 220 banner describing the host and capabilities.";
        var why = "Accurate banners aid troubleshooting and security while TLS advertisement encourages encrypted connections.";

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
                Highlights = new List<string> { "No SMTP banner data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        foreach (var kv in analysis.ServerResults)
        {
            var r = kv.Value;
            hi.Add($"{kv.Key} banner: {r?.Banner ?? "(none)"}");
            if (!string.IsNullOrWhiteSpace(analysis.ExpectedHostname))
            {
                hi.Add(r?.HostnameMatch == true
                    ? $"Hostname matches expected {analysis.ExpectedHostname}."
                    : $"Hostname mismatch for expected {analysis.ExpectedHostname}.");
            }
            hi.Add(r?.TlsAdvertised == true ? "TLS advertised in banner." : "No TLS advertised in banner.");
        }

        try
        {
            if (assessments != null)
            {
                AssessmentSplit.SplitTitles(assessments, out positives, out remediations);
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
        "https://www.rfc-editor.org/rfc/rfc5321"
    };
}

