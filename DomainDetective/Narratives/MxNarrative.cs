using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Narratives;

public static class MxNarrative
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

    public static Sections Build(MXAnalysis mx)
    {
        var subj = string.IsNullOrWhiteSpace(mx?.Subject) ? "(domain)" : mx.Subject;
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
        var remediations = new List<string>();

        hi.Add($"MX records: {mx.MxRecords?.Count ?? 0}");
        hi.Add(mx.PrioritiesInOrder ? "Priorities are in ascending order." : "Priorities appear out of order.");
        hi.Add(mx.Ipv6Supported ? "IPv6 supported on at least one MX host." : "No IPv6 support detected on MX hosts.");

        det.Add(mx.HasBackupServers ? "Multiple MX preferences provide redundancy." : "Only a single MX preference detected.");
        if (!mx.Ipv6Supported)
            det.Add("Consider adding AAAA records for IPv6 reachability.");

        var refs = mx.RfcReferences?.Select(r => string.IsNullOrWhiteSpace(r.Url) ? r.Reference : r.Url).ToList()
            ?? new List<string> { "https://www.rfc-editor.org/rfc/rfc5321" };

        try
        {
            var assessments = (IEnumerable<Assessment>)(mx.Assessments ?? new List<Assessment>());
            var groups = RecommendationEngine.GroupByCode(assessments);
            foreach (var g in groups)
            {
                var msg = string.IsNullOrWhiteSpace(g.Advice?.Title)
                    ? (g.Instances.FirstOrDefault()?.Message ?? g.Code)
                    : g.Advice.Title;
                if (g.MaxSeverity == AssessmentSeverity.Info)
                    positives.Add(msg);
                else
                    remediations.Add(msg);
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
            Remediations = remediations.Distinct(StringComparer.OrdinalIgnoreCase).ToList()
        };
    }
}
