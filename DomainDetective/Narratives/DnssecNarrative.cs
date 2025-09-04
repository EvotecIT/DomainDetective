using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective;
using DomainDetective.Protocols;

namespace DomainDetective.Narratives;

public static class DnssecNarrative
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

    public static Sections Build(DnsSecAnalysis analysis, IEnumerable<Assessment>? assessments = null)
    {
        var subject = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject!;
        var title = $"DNSSEC Report — {subject}";
        var subtitle = "DNSSEC Assessment";
        var category = "DNS Security";
        var keywords = $"DNSSEC, DNS, security, DomainDetective, {subject}";
        var creator = "DomainDetective";
        var intro = "Domain Name System Security Extensions (DNSSEC) add digital signatures to DNS records to verify their integrity.";
        var why = "Valid DNSSEC signatures help protect users from forged DNS responses and cache poisoning.";

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
                Highlights = new List<string> { "No DNSSEC data available." },
                Details = det,
                References = DefaultRefs()
            };
        }

        hi.Add(analysis.DsRecords.Count > 0 ? "DS record present at parent." : "No DS record found at parent.");

        if (analysis.DnsKeys.Count > 0)
        {
            var algs = new List<string>();
            foreach (var key in analysis.DnsKeys)
            {
                var parts = key.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 3 && int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var alg))
                {
                    var name = DNSKeyAnalysis.AlgorithmName(alg);
                    if (!string.IsNullOrEmpty(name))
                    {
                        algs.Add(name);
                    }
                }
            }
            var distinct = algs.Distinct().ToList();
            hi.Add(distinct.Count > 0
                ? $"Key algorithms: {string.Join(", ", distinct)}."
                : "Key algorithms: unknown.");
        }
        else
        {
            hi.Add("No DNSKEY records returned.");
        }

        hi.Add(analysis.ChainValid ? "Chain of trust validated." : "Chain of trust invalid.");
        hi.Add(analysis.DsMatch ? "DS and DNSKEY match." : "DS and DNSKEY mismatch.");
        if (analysis.KeyExpiresSoon)
        {
            hi.Add("Some signatures expire soon.");
        }

        if (analysis.DsRecords.Count > 0)
        {
            det.AddRange(analysis.DsRecords.Select((d, i) => $"DS[{i + 1}]: {d}"));
        }

        var refs = DefaultRefs();

        try
        {
            var assess = assessments ?? analysis.Assessments;
            AssessmentSplit.SplitTitles(assess, out positives, out remediations);
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
            References = refs,
            Positives = positives,
            Remediations = remediations
        };
    }

    private static List<string> DefaultRefs() => new()
    {
        "https://www.rfc-editor.org/rfc/rfc4033",
        "https://www.rfc-editor.org/rfc/rfc4035"
    };
}
