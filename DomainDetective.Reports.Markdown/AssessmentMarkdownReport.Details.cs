using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using OfficeIMO.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Markdown;

public static partial class AssessmentMarkdownReport {
    private static void WriteCheckDetails(MarkdownDocument document, CheckAssessment check, AssessmentMarkdownOptions options) {
        document.H4(InlineText(check.Title + " · " + Wording.OutcomeLabel(check.Outcome)));
        document.P(InlineText(Wording.AreaLabel(check.Area) + " · "
            + (check.Scored && check.EvidenceComplete && check.Score.HasValue
                ? check.Score.Value.ToString(CultureInfo.InvariantCulture) + " / 100" : "Not scored")));
        if (!string.IsNullOrWhiteSpace(check.Description)) { document.P(InlineText(check.Description)); }
        if (!string.IsNullOrWhiteSpace(check.Summary)) { document.P(InlineText(check.Summary)); }
        if (!check.EvidenceComplete) { document.P(InlineText(Wording.DoFirstMessage(check))); }
        if (check.Metrics.Count > 0) {
            AddTable(document, new[] { "Key number", "Value", "Note" }, check.Metrics.Select(static metric =>
                new[] { metric.Label, metric.Value, metric.Note ?? string.Empty }));
        }
        CheckFinding[] findings = check.Findings.Where(f => options.ShowInfoFindings || f.Severity != AssessmentSeverity.Info).ToArray();
        if (findings.Length > 0) {
            document.H5("Findings");
            AddTable(document, new[] { "Severity", "Finding", "Where", "Code" }, findings.Select(static finding => new[] {
                Wording.FindingLabel(finding),
                finding.Message, finding.Target ?? string.Empty, finding.Code ?? string.Empty
            }));
        }
        if (check.Positives.Count > 0) {
            document.H5("What works");
            AddBullets(document, check.Positives);
        }
        WriteGuidance(document, check);
        WriteEvidence(document, check);
    }

    private static void WriteGuidance(MarkdownDocument document, CheckAssessment check) {
        string? why = check.Narrative?.WhyItMatters;
        if (!string.IsNullOrWhiteSpace(why)) {
            document.H5("Why it matters");
            document.P(InlineText(why));
        }
        bool needsFix = check.Outcome is CheckOutcome.Error or CheckOutcome.Warning;
        if (needsFix && check.Recommendations.Count > 0) {
            document.H5("What to do");
            foreach (CheckGuidance guidance in check.Recommendations) {
                document.P(p => p.Bold(InlineText(guidance.Title)));
                string detail = string.Join(" ", new[] { guidance.How, guidance.Why }.Where(static text => !string.IsNullOrWhiteSpace(text)));
                if (detail.Length > 0) { document.P(InlineText(detail)); }
                if (!string.IsNullOrWhiteSpace(guidance.Verify)) { document.P(InlineText("Verify: " + guidance.Verify)); }
            }
        } else {
            List<string> remediations = check.Narrative?.Remediations.Where(static r => !string.IsNullOrWhiteSpace(r)).ToList() ?? new List<string>();
            if (remediations.Count == 0 && needsFix && !string.IsNullOrWhiteSpace(check.Remediation)) { remediations.Add(check.Remediation!); }
            if (remediations.Count > 0) {
                document.H5("What to do");
                AddBullets(document, remediations);
            }
        }
        if (check.References.Count > 0) {
            document.H5("References");
            AddBullets(document, check.References);
        }
    }

    private static void WriteEvidence(MarkdownDocument document, CheckAssessment check) {
        if (check.Highlights.Count == 0 && check.Facts.Count == 0 && check.Evidence.Count == 0) { return; }
        document.H5("Evidence");
        AddBullets(document, check.Highlights);
        if (check.Facts.Count > 0) {
            // These labels and values already apply the shared presentation map and Not attributed rules.
            AddTable(document, new[] { "Fact", "Value" }, check.Facts.Select(static fact => new[] { fact.Label, fact.Value }));
        }
        foreach (CheckEvidence evidence in check.Evidence) {
            document.H6(InlineText(evidence.Title));
            switch (evidence.Kind) {
                case CheckEvidenceKind.Code:
                    document.Code("text", evidence.Text ?? string.Empty);
                    break;
                case CheckEvidenceKind.List:
                    AddBullets(document, evidence.Items);
                    break;
                case CheckEvidenceKind.Table:
                    AddTable(document, evidence.Columns, evidence.Rows);
                    break;
            }
            if (evidence.Omitted > 0) {
                document.P(evidence.Omitted.ToString("N0", CultureInfo.InvariantCulture)
                    + " " + (evidence.Kind == CheckEvidenceKind.Table ? "rows" : "items")
                    + " omitted from the assessment model; not available in this export.");
            }
        }
    }

    private static void AddBullets(MarkdownDocument document, IEnumerable<string> values) {
        string[] items = values.Select(InlineText).ToArray();
        if (items.Length > 0) { document.Ul(list => list.Items(items)); }
    }
}
