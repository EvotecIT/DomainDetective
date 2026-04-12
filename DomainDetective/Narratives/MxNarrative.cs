using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Providers.Email;

namespace DomainDetective.Narratives;

/// <summary>Provides mx narrative functionality.</summary>
public static class MxNarrative
{
/// <summary>Structured narrative sections for MX analysis.</summary>
public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(MXAnalysis mx)
    {
        var subj = string.IsNullOrWhiteSpace(mx.Subject) ? "(domain)" : mx.Subject;
        var title = $"MX Report — {subj}";
        var subtitle = "MX Assessment";
        var category = "Email Security";
        var keywords = $"MX, email, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Mail Exchanger (MX) records direct email for a domain to the correct mail servers.";
        var why = "Proper MX configuration ensures reliable and resilient inbound mail delivery.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        hi.Add($"MX records: {mx.MxRecords?.Count ?? 0}");
        hi.Add(mx.PrioritiesInOrder ? "Priorities are in ascending order." : "Priorities appear out of order.");
        hi.Add(mx.Ipv6Supported ? "IPv6 supported on at least one MX host." : "No IPv6 support detected on MX hosts.");

        det.Add(mx.HasBackupServers ? "Multiple MX preferences provide redundancy." : "Only a single MX preference detected.");
        if (!mx.Ipv6Supported)
            det.Add("Consider adding AAAA records for IPv6 reachability.");

        // Provider summary from MX hosts (best-effort; fuller detection happens at DomainHealthCheck level)
        try {
            var hosts = (mx.MxRecords ?? new List<string>())
                .Select(rr => rr?.Split(new[]{' ','\t'}, 2, StringSplitOptions.RemoveEmptyEntries))
                .Where(p => p != null && p.Length > 0)
                .Select(p => p!.Length == 2 ? p![1] : p![0])
                .Where(h => !string.IsNullOrWhiteSpace(h))
                .Select(h => h.Trim('.'))
                .ToList();
            var match = EmailProviderDetector.Detect(hosts);
            if (match?.Primary != null)
                hi.Add($"Primary provider inferred: {match.Primary.DisplayName}.");
            if (match != null && match.Gateways.Count > 0)
                det.Add($"Gateway(s): {string.Join(", ", match.Gateways.Select(g => g.DisplayName).Distinct())}.");
        } catch { }

        var refsList = mx.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList();
        var refs = refsList ?? new List<string> { "https://www.rfc-editor.org/rfc/rfc5321" };

        try
        {
            var assessments = (IEnumerable<Assessment>)(mx.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                var adviceTitle = g.Advice?.Title;
                string msg;
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
}
