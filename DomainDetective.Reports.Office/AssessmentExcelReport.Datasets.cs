using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    private static void WriteChecks(ExcelSheet sheet, DomainAssessmentReport report, IReadOnlyDictionary<CheckAssessment, int> evidenceRows) {
        bool several = Several(report);
        int count = report.Domains.Sum(static d => d.Checks.Count);
        Title(sheet, "Checks · " + Scope(report), Wording.Plural(count, "check")
            + ". Score is blank for informational checks and checks whose evidence was incomplete. Check names link to their evidence.");
        const int header = 4;
        WriteHeader(sheet, header, several
            ? new[] { "Domain", "Check", "Area", "Outcome", "Score", "What was found" }
            : new[] { "Check", "Area", "Outcome", "Score", "What was found" });
        int offset = several ? 1 : 0;
        int row = header;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                WriteRow(sheet, ++row, Row(several, domain.Domain, check.Title, Wording.AreaLabel(check.Area), Wording.OutcomeLabel(check.Outcome),
                    check.Scored && check.EvidenceComplete ? check.Score : null, Details(check)));
                if (several) { sheet.Cell(row, 1).SetFontFamily(Mono); }
                if (evidenceRows.TryGetValue(check, out int target)) { Link(sheet, row, 1 + offset, EvidenceSheet, target, check.Title); }
                sheet.Cell(row, 1 + offset).SetBold();
                Tone(sheet, row, 3 + offset, OutcomeColor(check.Outcome));
            }
        }
        ScoreBars(sheet, ColumnName(4 + offset), header + 1, row);
        Table(sheet, "Checks", header, row, 5 + offset, several ? new double[] { 26, 30, 11, 12, 9, 96 } : new double[] { 30, 11, 12, 9, 96 });
        Wrap(sheet, header + 1, row, 5 + offset);
        Paper(sheet, header, 1 + offset, Tabs[1]);
    }

    /// <summary>One plain-words line: the key number, then the top warning or error and how many more there are.</summary>
    private static string Details(CheckAssessment check) {
        var parts = new List<string>();
        if (Wording.Headline(check) is { } headline) {
            parts.Add(headline.Label + ": " + headline.Value);
        } else if (check.Metrics.Count > 0) {
            parts.Add(string.Join(" · ", check.Metrics.Take(3).Select(static m => m.Label + ": " + m.Value)));
        }
        string? finding = Wording.TopFinding(check) ?? (!check.EvidenceComplete ? Wording.DoFirstMessage(check) : null);
        if (finding != null) {
            parts.Add(finding + (OfficeScoreText.MoreFindings(check) is { } more ? " (" + more + ")" : string.Empty));
        }
        // Without a key number or finding, the check's own plain sentences say what it established.
        if (parts.Count == 0 && check.Positives.Count > 0) { parts.Add(string.Join("; ", check.Positives.Take(3).Select(static p => p.TrimEnd('.'))) + "."); }
        if (parts.Count == 0 && !string.IsNullOrWhiteSpace(check.Summary)) { parts.Add(check.Summary!); }
        return string.Join(" · ", parts);
    }

    private static void WriteFindings(ExcelSheet sheet, DomainAssessmentReport report, AssessmentExcelOptions options) {
        bool several = Several(report);
        // HTML's hidden navigation IDs are not evidence and have no workbook target.
        Title(sheet, "Findings · " + Scope(report), options.ShowInfoFindings
            ? "Every finding, including informational notes." : "Warnings, errors and incomplete evidence. Informational notes are left out.");
        const int header = 4;
        WriteHeader(sheet, header, several
            ? new[] { "Severity", "Domain", "Check", "Finding", "Where", "Code", "Area" }
            : new[] { "Severity", "Check", "Finding", "Where", "Code", "Area" });
        int offset = several ? 1 : 0;
        int row = header;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                foreach (CheckFinding finding in check.Findings.Where(f => options.ShowInfoFindings || f.Severity != AssessmentSeverity.Info)) {
                    var values = new List<object?> { Wording.FindingLabel(finding) };
                    if (several) { values.Add(domain.Domain); }
                    values.AddRange(new object?[] {
                        check.Title, finding.Message,
                        string.Equals(finding.Target, domain.Domain, StringComparison.OrdinalIgnoreCase) ? null : finding.Target,
                        finding.Code, Wording.AreaLabel(check.Area)
                    });
                    WriteRow(sheet, ++row, values.ToArray());
                    Tone(sheet, row, 1, finding.IsEvidenceGap ? Muted : finding.Severity == AssessmentSeverity.Error ? High
                        : finding.Severity == AssessmentSeverity.Warning ? Elevated : Informational);
                    if (several) { sheet.Cell(row, 2).SetFontFamily(Mono); }
                    sheet.Cell(row, 2 + offset).SetBold();
                    sheet.Cell(row, 4 + offset).SetFontFamily(Mono);
                    sheet.Cell(row, 5 + offset).SetFontFamily(Mono);
                    sheet.Cell(row, 5 + offset).SetColor(OfficeColor.Parse(Muted));
                }
            }
        }
        if (row == header) { WriteCell(sheet, ++row, 1, "No findings."); }
        Table(sheet, "Findings", header, row, 6 + offset, several
            ? new double[] { 12, 26, 22, 80, 40, 36, 11 } : new double[] { 12, 22, 80, 40, 36, 11 });
        // Only the finding wraps; long target lists stay on one line and keep their full value in the cell.
        Wrap(sheet, header + 1, row, 3 + offset);
        Paper(sheet, header, 1, Tabs[1]);
    }
}
