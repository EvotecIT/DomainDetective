using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class DmarcNarrative
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

    public static Sections Build(DmarcAnalysis dmarc)
    {
        var subj = string.IsNullOrWhiteSpace(dmarc?.Subject) ? "(domain)" : dmarc.Subject;
        var title = $"DMARC Report — {subj}";
        var subtitle = "DMARC Assessment";
        var category = "Email Security";
        var keywords = $"DMARC, email, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "Domain-based Message Authentication, Reporting, and Conformance (DMARC) lets a domain specify policy for handling spoofed mail and receive feedback reports.";
        var why = "DMARC reduces impersonation by requiring alignment of SPF and/or DKIM with the visible From domain, and enables receivers to report abuse.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var remediations = new List<string>();

        // Highlights
        hi.Add(dmarc.DmarcRecordExists
            ? "DMARC record is published."
            : "No DMARC record is published.");
        if (dmarc.DmarcRecordExists && dmarc.StartsCorrectly)
            hi.Add("Record starts with v=DMARC1.");

        if (!string.IsNullOrWhiteSpace(dmarc.Policy))
        {
            hi.Add($"Policy: {dmarc.Policy}{(dmarc.Policy.Equals("No policy", StringComparison.OrdinalIgnoreCase) ? " (monitoring only)" : string.Empty)}");
        }

        if (!string.IsNullOrWhiteSpace(dmarc.SubPolicy))
        {
            hi.Add($"Subdomain policy: {dmarc.SubPolicy}");
        }

        if (!string.IsNullOrWhiteSpace(dmarc.DkimAlignment) || !string.IsNullOrWhiteSpace(dmarc.SpfAlignment))
        {
            hi.Add($"Alignment: DKIM={dmarc.DkimAlignment ?? "?"}, SPF={dmarc.SpfAlignment ?? "?"}");
        }
        // Strict alignment positives
        if (string.Equals(dmarc.DkimAlignment, "Strict", StringComparison.OrdinalIgnoreCase))
            hi.Add("DKIM alignment is strict (adkim=s).");
        if (string.Equals(dmarc.SpfAlignment, "Strict", StringComparison.OrdinalIgnoreCase))
            hi.Add("SPF alignment is strict (aspf=s).");

        var ruaCount = dmarc.MailtoRua?.Count ?? 0;
        var rufCount = (dmarc.MailtoRuf?.Count ?? 0) + (dmarc.HttpRuf?.Count ?? 0);
        hi.Add($"Aggregate reporting (rua): {(ruaCount > 0 ? ruaCount + " address(es)" : "none")}");
        hi.Add($"Forensic reporting (ruf): {(rufCount > 0 ? rufCount + " address(es)" : "none")}");

        // Details
        if (!string.IsNullOrWhiteSpace(dmarc.ReportingInterval))
            det.Add($"Reporting interval: {dmarc.ReportingInterval}");
        if (!string.IsNullOrWhiteSpace(dmarc.Percent))
        {
            det.Add(dmarc.Percent);
            if (dmarc.Percent.StartsWith("100%", StringComparison.OrdinalIgnoreCase))
                hi.Add("pct=100 (full enforcement).");
        }

        if (dmarc.MailtoRua != null && dmarc.MailtoRua.Count > 0)
            det.Add($"rua: {string.Join(", ", dmarc.MailtoRua)}");
        if (dmarc.HttpRua != null && dmarc.HttpRua.Count > 0)
            det.Add($"rua (http): {string.Join(", ", dmarc.HttpRua)}");
        if (dmarc.MailtoRuf != null && dmarc.MailtoRuf.Count > 0)
            det.Add($"ruf: {string.Join(", ", dmarc.MailtoRuf)}");
        if (dmarc.HttpRuf != null && dmarc.HttpRuf.Count > 0)
            det.Add($"ruf (http): {string.Join(", ", dmarc.HttpRuf)}");

        if (dmarc.ExternalReportAuthorization != null && dmarc.ExternalReportAuthorization.Count > 0)
        {
            var ext = dmarc.ExternalReportAuthorization
                .Select(kvp => $"{kvp.Key}:{(kvp.Value ? "authorized" : "unauthorized")}")
                .ToArray();
            det.Add($"External reporting domains: {string.Join(", ", ext)}");
        }

        if (!string.IsNullOrWhiteSpace(dmarc.Advisory))
            det.Add($"Advisory: {dmarc.Advisory}");

        // References
        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc7489",
            "https://datatracker.ietf.org/doc/html/draft-ietf-dmarcbis-base"
        };

        try
        {
            AssessmentSplit.SplitTitles(dmarc.Assessments ?? new List<Assessment>(), out positives, out remediations);
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
