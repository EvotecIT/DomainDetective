using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides dnsbl narrative functionality.</summary>
public static class DnsblNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(DNSBLAnalysis? analysis, IEnumerable<Assessment>? assessments = null)
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
        var title = $"DNSBL Report — {subj}";
        var subtitle = "DNS Blocklist Assessment";
        var category = "Threat Intelligence";
        var keywords = $"DNSBL, blacklist, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "DNS-based block lists (DNSBL) report hosts associated with spam or abuse.";
        var why = "Regularly checking DNSBLs helps protect delivery reputation and detect compromise.";

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
                Highlights = new List<string> { "No DNSBL data available." },
                Details = det,
                References = new List<string> { "https://datatracker.ietf.org/doc/html/rfc5782" }
            };
        }

        hi.Add($"Providers checked: {analysis.GetDNSBL().Count}");
        hi.Add($"Hosts checked: {analysis.RecordChecked}");
        hi.Add(analysis.Blacklisted > 0
            ? $"Hosts listed: {analysis.Blacklisted}"
            : "No hosts were listed on DNSBLs.");

        foreach (var kv in analysis.Results)
        {
            det.Add($"{kv.Key}: listed {kv.Value.Listed}/{kv.Value.Total}");
        }

        var refs = new List<string> { "https://datatracker.ietf.org/doc/html/rfc5782" };

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
            References = refs,
            Positives = positives,
            Negatives = negatives,
            Remediations = remediations
        };
    }
}

