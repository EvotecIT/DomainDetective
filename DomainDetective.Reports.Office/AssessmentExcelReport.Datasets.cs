using System;
using System.Linq;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    private static void WriteChecks(ExcelSheet sheet, DomainAssessmentReport report) {
        // The user-facing HTML Explore Checks columns, including its optional long-text columns.
        WriteHeader(sheet, 1, "Domain", "Area", "Check", "Outcome", "Key number", "Score", "Errors", "Warnings", "Top finding", "Key numbers", "Summary");
        int row = 1;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                CheckMetric? headline = Wording.Headline(check);
                WriteRow(sheet, ++row, domain.Domain, Wording.AreaLabel(check.Area), check.Title, Wording.OutcomeLabel(check.Outcome),
                    headline == null ? string.Empty : headline.Label + ": " + headline.Value,
                    check.Scored && check.EvidenceComplete ? (object?)check.Score ?? "Not scored" : "Not scored",
                    check.ErrorCount, check.WarningCount, Wording.TopFinding(check),
                    string.Join(" · ", check.Metrics.Select(static m => m.Label + ": " + m.Value)), check.Summary ?? check.Description);
                sheet.CellFontName(row, 1, "Consolas");
                sheet.CellFontColor(row, 4, OutcomeColor(check.Outcome));
                if (!check.Scored || !check.EvidenceComplete || !check.Score.HasValue || check.Score == 0) { sheet.CellFontColor(row, 6, Muted); }
                sheet.CellFontColor(row, 7, check.ErrorCount == 0 ? Muted : High);
                sheet.CellFontColor(row, 8, check.WarningCount == 0 ? Muted : Elevated);
            }
        }
        FinishSheet(sheet, 1, row, 11, (1, 32), (9, 50), (10, 50), (11, 50));
    }

    private static void WriteFindings(ExcelSheet sheet, DomainAssessmentReport report, AssessmentExcelOptions options) {
        // HTML's hidden navigation IDs are not evidence and have no workbook target.
        WriteHeader(sheet, 1, "Severity", "Domain", "Check", "Finding", "Where", "Code", "Area");
        int row = 1;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                foreach (CheckFinding finding in check.Findings.Where(f => options.ShowInfoFindings || f.Severity != AssessmentSeverity.Info)) {
                    string severity = Wording.FindingLabel(finding);
                    WriteRow(sheet, ++row, severity, domain.Domain, check.Title, finding.Message,
                        string.Equals(finding.Target, domain.Domain, StringComparison.OrdinalIgnoreCase) ? string.Empty : finding.Target,
                        finding.Code, Wording.AreaLabel(check.Area));
                    sheet.CellFontColor(row, 1, finding.IsEvidenceGap ? Muted : finding.Severity == AssessmentSeverity.Error ? High
                        : finding.Severity == AssessmentSeverity.Warning ? Elevated : Informational);
                    sheet.CellFontName(row, 2, "Consolas");
                    sheet.CellFontName(row, 5, "Consolas");
                    sheet.CellFontName(row, 6, "Consolas");
                }
            }
        }
        FinishSheet(sheet, 1, row, 7, (2, 32), (4, 65), (5, 36), (6, 32));
    }
}
