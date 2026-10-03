using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective;

namespace DomainDetective.Narratives;

/// <summary>Provides dmarc narrative functionality.</summary>
public static class DmarcNarrative
{
    /// <summary>Provides sections functionality.</summary>
    public sealed class Sections : NarrativeSections { }

    /// <summary>Executes the build operation.</summary>
    public static Sections Build(DmarcAnalysis dmarc)
    {
        var subj = string.IsNullOrWhiteSpace(dmarc.Subject) ? "(domain)" : dmarc.Subject;
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
        var negatives = new List<string>();
        var remediations = new List<string>();

        // Highlights
        hi.Add(dmarc.DmarcRecordExists
            ? "DMARC record is published."
            : "No DMARC record is published.");
        if (dmarc.DmarcRecordExists && dmarc.StartsCorrectly)
            hi.Add("Record starts with v=DMARC1.");

        if (!string.IsNullOrWhiteSpace(dmarc.Policy))
        {
            hi.Add($"Published policy: {dmarc.Policy}");
        }
        if (!string.IsNullOrEmpty(dmarc.EffectivePolicyShort))
            hi.Add($"Effective policy: {dmarc.EffectivePolicyShort}{(dmarc.IsTestMode ? " (test mode)" : string.Empty)}.");
        if (dmarc.DnsQueryFailed) hi.Add("Policy discovery failed; policy absence was not established.");
        if (dmarc.ReportingQueryFailed) hi.Add("Reporting query failed; authorization was not established for every destination.");

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
            det.Add($"Legacy sampling percentage: {dmarc.Percent}");
            if (dmarc.Assessments.Any(assessment => assessment.Code == DmarcCodes.Percent100))
                hi.Add("Legacy percentage tag pct=100 is published.");
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
            "https://www.rfc-editor.org/rfc/rfc9989.html"
        };

        try
        {
            (positives, negatives, remediations) = AssessmentSplit.SplitTitles(dmarc.Assessments ?? new List<Assessment>());
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
