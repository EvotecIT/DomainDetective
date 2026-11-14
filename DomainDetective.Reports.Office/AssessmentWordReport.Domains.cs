using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    private static void WriteDomain(WordDocument document, WordPaperStyle style, DomainAssessment domain, AssessmentWordOptions options) {
        Heading(document, style, Identifier(domain.Domain) + " · "
            + (domain.Score.HasValue ? domain.Grade + " · " + Score(domain.Score) : "Not scored"), 1, newPage: true);
        Cards(document, style, domain.Checks.GroupBy(c => c.Area).OrderBy(g => AreaIndex(g.Key)).Select(group => {
            int? score = domain.Areas.FirstOrDefault(a => a.Area == group.Key)?.Score;
            return (Wording.AreaLabel(group.Key), Score(score), ScoreTone(score));
        }));
        foreach (var group in domain.Checks.GroupBy(c => c.Area).OrderBy(g => AreaIndex(g.Key))) {
            Heading(document, style, Wording.AreaLabel(group.Key), 2);
            // Keep canonical order within the two groups; every non-pass outcome precedes passing checks.
            List<CheckAssessment> checks = group.OrderBy(c => c.Outcome == CheckOutcome.Pass ? 1 : 0).ToList();
            WordTable table = Table(document, style, new[] { "Check", "Outcome", "Key number", "Top finding" },
                checks.Select(c => new[] { c.Title, Wording.OutcomeLabel(c.Outcome), HeadlineText(c), Wording.TopFinding(c) ?? string.Empty }), 18, 14, 23, 45);
            for (int index = 0; index < checks.Count; index++) {
                style.ApplyCellTone(table.Rows[index + 1].Cells[1], OutcomeTone(checks[index].Outcome));
            }
            foreach (CheckAssessment check in checks.Where(c => Wording.NeedsAttention(c) || options.ShowInfoFindings && c.Findings.Count > 0)) {
                WriteAttention(document, style, domain, check, options);
            }
        }
    }

    private static string HeadlineText(CheckAssessment check) => Wording.Headline(check) is { } metric
        ? metric.Label + ": " + metric.Value : string.Empty;

    private static void WriteAttention(WordDocument document, WordPaperStyle style, DomainAssessment domain, CheckAssessment check, AssessmentWordOptions options) {
        Heading(document, style, check.Title + " · " + Wording.OutcomeLabel(check.Outcome), 3);
        var findings = check.Findings.Where(f => options.ShowInfoFindings || f.Severity is AssessmentSeverity.Warning or AssessmentSeverity.Error).ToList();
        if (findings.Count == 0) { Body(document, style, Wording.DoFirstMessage(check)); }
        foreach (CheckFinding finding in findings) {
            WordParagraph message = Body(document, style, finding.Message);
            message.ColorHex = finding.IsEvidenceGap ? Neutral : finding.Severity == AssessmentSeverity.Error ? High : finding.Severity == AssessmentSeverity.Warning ? Elevated : Neutral;
            if (!string.IsNullOrWhiteSpace(finding.Target) || !string.IsNullOrWhiteSpace(finding.Code)) {
                WordParagraph location = style.AddNote(document, string.Join(" · ", new[] { finding.Target, finding.Code }
                    .Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => Identifier(s!))));
                location.FontFamily = Mono;
                location.LineSpacingBeforePoints = 0;
                location.LineSpacingAfterPoints = 4;
            }
        }
        WriteRecommendations(document, style, check);
        if (check.Highlights.Count > 0) {
            foreach (string highlight in check.Highlights) { Body(document, style, highlight); }
        }
        if (!check.EvidenceComplete && check.Metrics.Count > 0) {
            // An incomplete check has no headline. Preserve captured states such as Record: Unknown
            // here rather than depending on the appendix's former aggregate metric column.
            WordTable metrics = style.AddKeyValueTable(document, check.Metrics.Select(metric =>
                new KeyValuePair<string, string>(metric.Label, metric.Value)), allowRowSplit: true, hasHeader: false);
            metrics.SetColumnWidthsPercentage(32, 68);
            SizeTable(metrics);
            for (int index = 0; index < check.Metrics.Count; index++) {
                WordTableCell value = metrics.Rows[index].Cells[1];
                IdentifierValueCell(value);
                if (check.Metrics[index].State == MetricState.Neutral) { style.ApplyCellTone(value, Neutral); }
            }
        }
        if (check.Facts.Count > 0) {
            WordTable facts = style.AddKeyValueTable(document, check.Facts.Select(f =>
                new KeyValuePair<string, string>(f.Label, f.Value)), allowRowSplit: true, hasHeader: false);
            facts.SetColumnWidthsPercentage(32, 68);
            SizeTable(facts);
            foreach (WordTableRow row in facts.Rows) { IdentifierValueCell(row.Cells[1]); }
        }
        foreach (CheckEvidence evidence in check.Evidence) {
            if (evidence.Kind is CheckEvidenceKind.Code or CheckEvidenceKind.Table) {
                // Large technical data is printed once, in full, after the domain chapters.
                Note(document, style, evidence.Title + ": see "
                    + (evidence.Kind == CheckEvidenceKind.Code ? "Raw records" : "Table evidence")
                    + " in the appendix — " + Identifier(domain.Domain) + " · " + check.Title + ".");
            } else {
                WordTable list = style.AddKeyValueTable(document, evidence.Items.Select((value, index) =>
                    new KeyValuePair<string, string>(Number(index + 1), value)), evidence.Title, "Value", allowRowSplit: true);
                list.SetColumnWidthsPercentage(20, 80);
                SizeTable(list);
                foreach (WordTableRow row in list.Rows.Skip(1)) { IdentifierValueCell(row.Cells[1]); }
                OmissionNote(document, style, evidence);
            }
        }
    }

    private static void WriteRecommendations(WordDocument document, WordPaperStyle style, CheckAssessment check) {
        if (check.Recommendations.Count > 0) {
            foreach (CheckGuidance advice in check.Recommendations) {
                Body(document, style, "What to do · " + advice.Title, true).KeepWithNext = true;
                if (!string.IsNullOrWhiteSpace(advice.How)) { Body(document, style, advice.How!); }
            }
            return;
        }
        List<string> remediations = check.Narrative?.Remediations.Where(r => !string.IsNullOrWhiteSpace(r)).ToList() ?? new List<string>();
        if (remediations.Count == 0 && !string.IsNullOrWhiteSpace(check.Remediation)
            && check.Outcome is CheckOutcome.Error or CheckOutcome.Warning) { remediations.Add(check.Remediation!); }
        if (remediations.Count == 0) { return; }
        Body(document, style, "What to do", true).KeepWithNext = true;
        foreach (string remediation in remediations) { Body(document, style, remediation); }
    }

    private static void OmissionNote(WordDocument document, WordPaperStyle style, CheckEvidence evidence) {
        if (evidence.Omitted <= 0) { return; }
        style.AddNote(document, Number(evidence.Omitted) + " additional "
            + (evidence.Kind == CheckEvidenceKind.List ? "items" : "rows")
            + " were omitted when the assessment model was collected and are unavailable in this report.");
    }
}
