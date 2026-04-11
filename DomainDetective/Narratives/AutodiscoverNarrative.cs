using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

/// <summary>Provides autodiscover narrative functionality.</summary>
public static class AutodiscoverNarrative
{
    /// <summary>Structured narrative sections for Autodiscover analysis.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(AutodiscoverAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var s = analysis?.Subject;
        var subj = string.IsNullOrWhiteSpace(s) ? "(domain)" : s;
        var title = $"Autodiscover Report — {subj}";
        var subtitle = "Autodiscover Assessment";
        var category = "Email Configuration";
        var keywords = $"Autodiscover, email, configuration, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Autodiscover helps mail clients locate server settings automatically using DNS hints and a defined HTTP flow.";
        var why = "Reliable Autodiscover records and endpoints reduce manual setup and support secure, automatic client configuration.";

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
                Highlights = new List<string> { "No Autodiscover data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        // DNS highlights
        hi.Add(analysis.SrvRecordExists
            ? $"_autodiscover._tcp SRV points to {analysis.SrvTarget}:{analysis.SrvPort}."
            : "_autodiscover._tcp SRV record missing.");
        hi.Add(analysis.AutodiscoverCnameExists
            ? $"autodiscover.{subj} CNAME → {analysis.AutodiscoverTarget}."
            : $"autodiscover.{subj} CNAME missing.");
        hi.Add(analysis.AutoconfigCnameExists
            ? $"autoconfig.{subj} CNAME → {analysis.AutoconfigTarget}."
            : "autoconfig CNAME missing.");

        // HTTP highlights
        var endpoints = analysis.Endpoints ?? Array.Empty<AutodiscoverEndpointResult>();
        var success = endpoints.FirstOrDefault(e => e.XmlValid || e.JsonValid);
        if (success != null)
        {
            hi.Add(success.XmlValid
                ? $"Endpoint {success.FinalHost ?? success.Url} returned valid Autodiscover XML."
                : "Outlook JSON discovery returned an Autodiscover endpoint.");
        }
        else
        {
            hi.Add("No Autodiscover endpoint produced valid XML or JSON.");
        }

        // Endpoint details
        foreach (var e in endpoints)
        {
            var line = $"{e.Method}: {e.StatusCode}";
            if (e.XmlValid) line += " (valid XML)";
            if (e.JsonValid) line += " (valid JSON)";
            if (!string.IsNullOrWhiteSpace(e.FinalHost))
            {
                var rawUrl = e.FinalUrl ?? e.Url;
                string? host = null;
                if (!string.IsNullOrWhiteSpace(rawUrl) && Uri.TryCreate(rawUrl, UriKind.Absolute, out var parsed))
                {
                    host = parsed.Host;
                }
                if (!string.Equals(e.FinalHost, host, StringComparison.OrdinalIgnoreCase))
                    line += $" → {e.FinalHost}";
            }
            det.Add(line);
        }

        var refs = DefaultRefs();

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
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://learn.microsoft.com/exchange/client-developer/exchange-web-services/autodiscover",
        "https://learn.microsoft.com/outlook/troubleshoot/autodiscover/autodiscover-service-overview"
    };
}
