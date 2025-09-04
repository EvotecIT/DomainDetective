using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class AutodiscoverNarrative
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

    public static Sections Build(AutodiscoverAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
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
            if (!string.IsNullOrWhiteSpace(e.FinalHost) && !string.Equals(e.FinalHost, new Uri(e.FinalUrl ?? e.Url ?? string.Empty).Host, StringComparison.OrdinalIgnoreCase))
                line += $" → {e.FinalHost}";
            det.Add(line);
        }

        var refs = DefaultRefs();

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
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://learn.microsoft.com/exchange/client-developer/exchange-web-services/autodiscover",
        "https://learn.microsoft.com/outlook/troubleshoot/autodiscover/autodiscover-service-overview"
    };
}
