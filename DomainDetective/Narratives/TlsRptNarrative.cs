using System;
using System.Collections.Generic;
using DomainDetective;

namespace DomainDetective.Narratives;

public static class TlsRptNarrative
{
    public sealed class Sections : NarrativeSections { }

    public static Sections Build(TLSRPTAnalysis analysis, InternalLogger? logger = null)
    {
        var subj = string.IsNullOrWhiteSpace(analysis?.Subject) ? "(domain)" : analysis.Subject;
        var title = $"TLS-RPT Report — {subj}";
        var subtitle = "TLS-RPT Assessment";
        var category = "Email Security";
        var keywords = $"TLS-RPT, email, security, DomainDetective, {subj}";
        var creator = "DomainDetective";
        var intro = "SMTP TLS Reporting (TLS-RPT) lets senders receive reports about failed TLS connections.";
        var why = "Collecting TLS-RPT feedback helps uncover misconfigurations and enforce encrypted mail delivery.";

        var hi = new List<string>();
        var det = new List<string>();
        var positives = new List<string>();
        var negatives = new List<string>();
        var remediations = new List<string>();

        hi.Add(analysis.TlsRptRecordExists ? "TLS-RPT record is published." : "No TLS-RPT record is published.");
        if (analysis.StartsCorrectly)
        {
            hi.Add("Record starts with v=TLSRPTv1.");
        }
        hi.Add($"Report URIs: {analysis.MailtoRua?.Count ?? 0} mailto, {analysis.HttpRua?.Count ?? 0} https");
        if (analysis.PolicyValid)
        {
            hi.Add("TLS-RPT policy is valid.");
        }

        if (analysis.MailtoRua != null && analysis.MailtoRua.Count > 0)
        {
            det.Add($"rua: {string.Join(", ", analysis.MailtoRua)}");
        }
        if (analysis.HttpRua != null && analysis.HttpRua.Count > 0)
        {
            det.Add($"rua (https): {string.Join(", ", analysis.HttpRua)}");
        }
        if (analysis.InvalidRua != null && analysis.InvalidRua.Count > 0)
        {
            det.Add($"invalid rua: {string.Join(", ", analysis.InvalidRua)}");
        }
        if (analysis.UnknownTags != null && analysis.UnknownTags.Count > 0)
        {
            det.Add($"unknown tags: {string.Join(", ", analysis.UnknownTags)}");
        }

        var refs = new List<string>
        {
            "https://datatracker.ietf.org/doc/html/rfc8460"
        };

        try
        {
            AssessmentSplit.SplitTitles(analysis.Assessments ?? new List<Assessment>(), out positives, out negatives, out remediations);
        }
        catch (Exception ex)
        {
            logger?.WriteWarning($"Failed to split assessments: {ex.Message}");
            positives = new List<string>();
            remediations = new List<string>();
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
            Negatives = negatives,
            Remediations = remediations
        };
    }
}
