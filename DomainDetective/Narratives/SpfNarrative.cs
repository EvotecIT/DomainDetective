using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class SpfNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(SpfAnalysis spf)
    {
        var subj = string.IsNullOrWhiteSpace(spf.Subject) ? "(domain)" : spf.Subject;
        var title = $"SPF Report — {subj}";
        var subtitle = "SPF Assessment";
        var category = "Email Security";
        var keywords = $"SPF, email, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Sender Policy Framework (SPF) lets a domain publish which mail servers are allowed to send on its behalf. Receiving servers can use this policy to detect and block spoofed email.";
        var why = "SPF helps reduce impersonation and phishing by ensuring messages originate from authorized infrastructure. Together with DKIM and DMARC it provides robust protection against spoofing.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        // High-level highlights
        hi.Add(spf.SpfRecordExists
            ? "SPF record is published and begins with v=spf1."
            : "No SPF record is published.");
        var allMechanism = spf.AllMechanism;
        if (allMechanism != null && !string.IsNullOrWhiteSpace(allMechanism))
        {
            hi.Add($"Policy ends with '{allMechanism}'. {ExplainAll(allMechanism)}");
        }
        hi.Add($"DNS lookups used: {spf.DnsLookupsCount}/10 {(spf.ExceedsDnsLookups ? "(exceeds limit)" : "(within limit)")}");
        if (spf.UnknownMechanisms != null && spf.UnknownMechanisms.Count > 0)
            hi.Add($"Unknown mechanisms present: {string.Join(", ", spf.UnknownMechanisms.Distinct())}");

        // Details
        if (spf.IncludeRecords != null && spf.IncludeRecords.Count > 0)
            det.Add($"Includes: {string.Join(", ", spf.IncludeRecords.Distinct())}");
        if (spf.ResolvedIpv4Records != null && spf.ResolvedIpv4Records.Count > 0)
            det.Add($"Resolved IPv4 ranges: {spf.ResolvedIpv4Records.Count}");
        if (spf.ResolvedIpv6Records != null && spf.ResolvedIpv6Records.Count > 0)
            det.Add($"Resolved IPv6 ranges: {spf.ResolvedIpv6Records.Count}");
        if (!string.IsNullOrWhiteSpace(spf.Advisory))
            det.Add($"Advisory: {spf.Advisory}");
        if (spf.PermError)
            det.Add("Permanent error detected while evaluating the policy.");
        if (spf.EffectiveSpfSends)
            det.Add("Effective sending sources were identified from the policy.");

        // References
        var refs = new List<string>();
        if (spf.RfcReferences != null && spf.RfcReferences.Count > 0)
            refs.AddRange(spf.RfcReferences.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url));
        else
            refs.Add("https://datatracker.ietf.org/doc/html/rfc7208");

        // Split recommendations: positives (Info) vs remediations (Warning/Error)
        try
        {
            var assessments = (IEnumerable<Assessment>)(spf.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                string msg;
                var adviceTitle = g.Advice?.Title;
                if (adviceTitle == null || string.IsNullOrWhiteSpace(adviceTitle)) {
                    msg = g.Instances.FirstOrDefault()?.Message ?? g.Code;
                } else {
                    msg = adviceTitle;
                }
                if (g.MaxSeverity == AssessmentSeverity.Info)
                {
                    positives.Add(msg);
                }
                else
                {
                    negatives.Add(msg);
                    remediations.Add(msg);
                }
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
            Positives = positives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Negatives = negatives.Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }

    private static string ExplainAll(string all)
    {
        var t = all.Trim();
        return t switch
        {
            "-all" => "Fail all non-authorized senders (recommended for enforcement).",
            "~all" => "Softfail: non-authorized senders are marked but often still accepted; consider moving to -all when ready.",
            "+all" => "Pass all: effectively disables SPF checks; not recommended.",
            "?all" => "Neutral: receivers should not apply a definitive pass/fail; not recommended for enforcement.",
            _ => "Policy qualifier on 'all' determines how unauthorized sources are treated."
        };
    }
}
