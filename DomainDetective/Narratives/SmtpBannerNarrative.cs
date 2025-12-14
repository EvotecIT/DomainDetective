using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class SmtpBannerNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(SMTPBannerAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subjCandidate = analysis?.Subject;
        string subj;
        if (subjCandidate != null && !string.IsNullOrWhiteSpace(subjCandidate))
        {
            subj = subjCandidate;
        }
        else
        {
            subj = "(host)";
        }
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
        var negatives = new List<string>();
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
                (positives, negatives, remediations) = AssessmentSplit.SplitTitles(assessments);
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

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc5321"
    };
}

