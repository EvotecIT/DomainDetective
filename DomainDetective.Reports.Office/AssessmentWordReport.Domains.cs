using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    /// <summary>Findings printed in a check's block; the rest are counted and left to the workbook's Findings sheet.</summary>
    private const int FindingLimit = 5;

    /// <summary>List items printed in a check's block; longer lists say how many were left out and where they are.</summary>
    private const int ListLimit = 8;

    /// <summary>Captured facts printed in a check's block; the workbook's Evidence sheet keeps them all.</summary>
    private const int FactLimit = 12;

    private static void WriteDomain(WordDocument document, WordPaperStyle style, DomainAssessmentReport report, DomainAssessment domain, AssessmentWordOptions options) {
        Heading(document, style, Identifier(domain.Domain) + " · "
            + (domain.Score.HasValue ? domain.Grade + " · " + Score(domain.Score) : "Not scored"), 1, newPage: true);
        Panel(document, style, Wording.DomainVerdict(domain), domain.Score.HasValue && OfficeScoreText.Partial(domain.Coverage)
            ? new[] { "The score covers " + OfficeScoreText.Percent(domain.Coverage!.Value) + " of the scored checks; those with incomplete evidence are left out." }
            : new string[0],
            domain.ErrorChecks > 0 ? High : domain.WarningChecks > 0 ? Elevated : domain.Checks.Any(c => !c.EvidenceComplete) ? Neutral : Good);
        Cards(document, style, domain.Checks.GroupBy(c => c.Area).OrderBy(g => AreaIndex(g.Key)).Select(group => {
            AreaScore? area = domain.Areas.FirstOrDefault(a => a.Area == group.Key);
            // Reputation is judged by the risk profile; without a configuration score its card shows the risk instead.
            if (group.Key == AnalysisArea.Reputation && area?.Score == null && domain.RiskProfile is { } risk) {
                return (Wording.AreaLabel(group.Key), Wording.RiskValue(risk), RiskTone(risk), (string?)"Risk");
            }
            return (Wording.AreaLabel(group.Key), Score(area?.Score), ScoreTone(area?.Score),
                area?.Score != null && OfficeScoreText.Partial(area.Coverage) ? OfficeScoreText.Percent(area.Coverage!.Value) + " judged" : null);
        }));
        WriteRiskProfile(document, style, domain);
        foreach (var group in domain.Checks.GroupBy(c => c.Area).OrderBy(g => AreaIndex(g.Key))) {
            Heading(document, style, Wording.AreaLabel(group.Key), 2);
            // Keep canonical order within the two groups; every non-pass outcome precedes passing checks.
            List<CheckAssessment> checks = group.OrderBy(c => c.Outcome == CheckOutcome.Pass ? 1 : 0).ToList();
            WordTable table = Table(document, style, new[] { "Check", "Outcome", "Key number", "Top finding" },
                checks.Select(c => new[] { c.Title, Wording.OutcomeLabel(c.Outcome), HeadlineText(c), TopLine(c) }), 20, 12, 24, 44);
            for (int index = 0; index < checks.Count; index++) {
                WordTableRow row = table.Rows[index + 1];
                row.Cells[0].Paragraphs[0].Bold = true;
                style.ApplyCellTone(row.Cells[1], OutcomeTone(checks[index].Outcome));
                row.Cells[1].Paragraphs[0].Bold = true;
                if (checks[index].Outcome == CheckOutcome.Pass && Wording.TopFinding(checks[index]) == null) {
                    style.ApplyCellTone(row.Cells[3], Neutral);
                }
            }
            // Checks that couldn't run get a short block too, in grey, so the reason is on paper.
            foreach (CheckAssessment check in checks.Where(c => Wording.NeedsAttention(c) || (c.Scored && !c.EvidenceComplete) || options.ShowInfoFindings && c.Findings.Count > 0)) {
                WriteAttention(document, style, report, domain, check, options);
            }
        }
    }

    private static string HeadlineText(CheckAssessment check) => Wording.Headline(check) is { } metric
        ? metric.Label + ": " + metric.Value : string.Empty;

    /// <summary>The top warning or error; for a check without one, what it established in its own plain sentence.</summary>
    private static string TopLine(CheckAssessment check) => Wording.TopFinding(check)
        ?? (check.Outcome == CheckOutcome.Pass && check.Positives.Count > 0 ? check.Positives[0] : string.Empty);

    private static void WriteAttention(WordDocument document, WordPaperStyle style, DomainAssessmentReport report, DomainAssessment domain, CheckAssessment check, AssessmentWordOptions options) {
        string tone = OutcomeTone(check.Outcome);
        WordParagraph heading = Heading(document, style, check.Title + " · " + Wording.OutcomeLabel(check.Outcome), 3);
        heading.Borders.LeftStyle = WordBorderStyle.Single;
        heading.Borders.LeftSize = OfficeLength.Points(4);
        heading.Borders.LeftColor = OfficeColor.Parse(tone);
        heading.IndentationBefore = OfficeLength.Points(6);
        heading.LineSpacingBefore = OfficeLength.Points(10);
        var findings = check.Findings.Where(f => options.ShowInfoFindings || f.Severity is AssessmentSeverity.Warning or AssessmentSeverity.Error).ToList();
        if (findings.Count == 0) { Body(document, style, Wording.DoFirstMessage(check)); }
        foreach (CheckFinding finding in findings.Take(FindingLimit)) {
            WordParagraph message = Body(document, style, finding.Message);
            message.Color = OfficeColor.Parse(finding.IsEvidenceGap ? Neutral : finding.Severity == AssessmentSeverity.Error ? High : finding.Severity == AssessmentSeverity.Warning ? Elevated : Neutral);
            message.LineSpacingAfter = OfficeLength.Points(1);
            if (!string.IsNullOrWhiteSpace(finding.Target) || !string.IsNullOrWhiteSpace(finding.Code)) {
                message.KeepWithNext = true;
                WordParagraph location = style.AddNote(document, string.Join(" · ", new[] { finding.Target, finding.Code }
                    .Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => Identifier(s!))));
                location.FontFamily = Mono;
                location.LineSpacingBefore = OfficeLength.Points(0);
                location.LineSpacingAfter = OfficeLength.Points(4);
            }
        }
        if (findings.Count > FindingLimit) {
            Note(document, style, Number(findings.Count - FindingLimit) + " more " + (findings.Count - FindingLimit == 1 ? "finding" : "findings")
                + " for " + check.Title + " are listed on the Findings sheet of the Excel workbook.");
        }
        WriteRecommendations(document, style, check);
        if (check.Highlights.Count > 0) {
            // One quiet paragraph instead of a line per observation.
            Body(document, style, string.Join(" ", check.Highlights.Select(h => h.Trim()).Select(h => h.EndsWith(".") ? h : h + ".")))
                .Color = OfficeColor.Parse(style.Muted);
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
            WordTable facts = style.AddKeyValueTable(document, check.Facts.Take(FactLimit).Select(f =>
                new KeyValuePair<string, string>(f.Label, f.Value)), "Evidence", "Value", allowRowSplit: true);
            facts.SetColumnWidthsPercentage(32, 68);
            SizeTable(facts);
            foreach (WordTableRow row in facts.Rows.Skip(1)) { IdentifierValueCell(row.Cells[1]); }
            if (check.Facts.Count > FactLimit) {
                Note(document, style, "First " + Number(FactLimit) + " of " + Number(check.Facts.Count) + " facts shown; all "
                    + Number(check.Facts.Count) + " are on the Evidence sheet of the Excel workbook.");
            }
        }
        foreach (CheckEvidence evidence in check.Evidence) {
            if (evidence.Kind is CheckEvidenceKind.Code or CheckEvidenceKind.Table) {
                // Large technical data is printed once, after the domain chapters.
                Note(document, style, evidence.Title + ": " + (evidence.Kind == CheckEvidenceKind.Table && !PrintsInAppendix(report, check, evidence)
                    ? "on the Evidence sheet of the Excel workbook (" + Wording.Plural(evidence.Rows.Count, "row") + "; listed under Longer tables in the appendix)."
                    : "see " + (evidence.Kind == CheckEvidenceKind.Code ? "Raw records" : "Table evidence")
                        + " in the appendix — " + Identifier(domain.Domain) + " · " + check.Title + "."));
            } else {
                WordTable list = style.AddKeyValueTable(document, evidence.Items.Take(ListLimit).Select((value, index) =>
                    new KeyValuePair<string, string>(Number(index + 1), value)), evidence.Title, "Value", allowRowSplit: true);
                list.SetColumnWidthsPercentage(20, 80);
                SizeTable(list);
                foreach (WordTableRow row in list.Rows.Skip(1)) { IdentifierValueCell(row.Cells[1]); }
                if (evidence.Items.Count > ListLimit) {
                    Note(document, style, "First " + Number(ListLimit) + " of " + Number(evidence.Items.Count) + " shown; all "
                        + Number(evidence.Items.Count) + " are on the Evidence sheet of the Excel workbook.");
                }
                OmissionNote(document, style, evidence);
            }
        }
    }

    private static void WriteRecommendations(WordDocument document, WordPaperStyle style, CheckAssessment check) {
        if (check.Recommendations.Count > 0) {
            foreach (CheckGuidance advice in check.Recommendations) {
                Advice(document, style, "What to do · " + advice.Title, advice.How);
            }
            return;
        }
        List<string> remediations = check.Narrative?.Remediations.Where(r => !string.IsNullOrWhiteSpace(r)).ToList() ?? new List<string>();
        if (remediations.Count == 0 && !string.IsNullOrWhiteSpace(check.Remediation)
            && check.Outcome is CheckOutcome.Error or CheckOutcome.Warning) { remediations.Add(check.Remediation!); }
        if (remediations.Count == 0) { return; }
        Advice(document, style, "What to do", string.Join(" ", remediations));
    }

    /// <summary>A teal-ruled callout: the action title in bold and how to do it under it.</summary>
    private static void Advice(WordDocument document, WordPaperStyle style, string title, string? how) {
        var lines = string.IsNullOrWhiteSpace(how) ? new string[0] : new[] { how! };
        var paragraphs = new List<WordParagraph> { Body(document, style, title, true) };
        foreach (string line in lines) { paragraphs.Add(Body(document, style, line)); }
        for (int index = 0; index < paragraphs.Count; index++) {
            WordParagraph paragraph = paragraphs[index];
            paragraph.ShadingFillColor = OfficeColor.Parse(Tint(Accent));
            paragraph.Borders.LeftStyle = WordBorderStyle.Single;
            paragraph.Borders.LeftSize = OfficeLength.Points(3);
            paragraph.Borders.LeftColor = OfficeColor.Parse(Accent);
            paragraph.IndentationBefore = OfficeLength.Points(8);
            paragraph.LineSpacingBefore = OfficeLength.Points(index == 0 ? 6 : 0);
            paragraph.LineSpacingAfter = OfficeLength.Points(index == paragraphs.Count - 1 ? 8 : 0);
            paragraph.KeepWithNext = index < paragraphs.Count - 1;
        }
    }

    private static void OmissionNote(WordDocument document, WordPaperStyle style, CheckEvidence evidence) {
        if (evidence.Omitted <= 0) { return; }
        style.AddNote(document, Number(evidence.Omitted) + " additional "
            + (evidence.Kind == CheckEvidenceKind.List ? "items" : "rows")
            + " were omitted when the assessment model was collected and are unavailable in this report.");
    }
}
