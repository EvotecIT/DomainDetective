using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

/// <summary>Writes a paper-style workbook from the same assessment used by the HTML report.</summary>
public static partial class AssessmentExcelReport {
    /// <summary>Writes summary, actions, checks, findings and captured-evidence worksheets.</summary>
    /// <param name="path">Destination workbook path. Its directory is created if needed.</param>
    /// <param name="report">The assessment, including presentation-ready evidence.</param>
    /// <param name="options">Optional export settings.</param>
    public static void Generate(string path, DomainAssessmentReport report, AssessmentExcelOptions? options = null) {
        if (string.IsNullOrWhiteSpace(path)) { throw new ArgumentException("An output path is required.", nameof(path)); }
        if (report == null) { throw new ArgumentNullException(nameof(report)); }
        options ??= new AssessmentExcelOptions();
        if (options.FixFirstCount < 1) { throw new ArgumentOutOfRangeException(nameof(options), "FixFirstCount must be positive."); }
        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        using ExcelDocument workbook = ExcelDocument.Create(fullPath);
        WriteSummary(workbook.AddWorksheet("Summary"), report);
        WriteActions(workbook.AddWorksheet("Do these first"), report, options);
        WriteChecks(workbook.AddWorksheet("Checks"), report);
        WriteFindings(workbook.AddWorksheet("Findings"), report, options);
        WriteCapturedEvidence(workbook.AddWorksheet("Evidence"), report);
        WriteEvidence(workbook, report);
        workbook.Save();
    }

    private static void WriteSummary(ExcelSheet sheet, DomainAssessmentReport report) {
        WriteRow(sheet, 1, Wording.ReportVerdict(report));
        sheet.CellBold(1, 1);
        sheet.CellFontSize(1, 1, 10.5);
        WriteRow(sheet, 2, Wording.ReportVerdictDetail(report));
        WriteRow(sheet, 4, "Grade / score", report.Score.HasValue
            ? report.Grade + " · " + report.Score.Value.ToString(CultureInfo.InvariantCulture) + " / 100" : "Not scored");
        if (!report.Score.HasValue || report.Score == 0) { sheet.CellFontColor(4, 2, Muted); }
        WriteRow(sheet, 5, "Generated", Wording.FormatTime(report.GeneratedAtUtc));
        WriteRow(sheet, 6, Wording.ScoreNote(report));
        sheet.CellFontColor(6, 1, Muted);
        const int header = 8;
        WriteHeader(sheet, header, "Area", "Status", "Score", "Checks", "Passing", "Needs attention", "Notes");
        int row = header;
        List<CheckAssessment> all = report.Domains.SelectMany(static d => d.Checks).ToList();
        foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
            List<CheckAssessment> checks = all.Where(c => c.Area == area).ToList();
            if (checks.Count == 0) { continue; }
            int[] scores = report.Domains.SelectMany(static d => d.Areas)
                .Where(a => a.Area == area && a.Score.HasValue).Select(static a => a.Score!.Value).ToArray();
            int? score = scores.Length == 0 || checks.Any(static c => c.Scored && !c.EvidenceComplete)
                ? null : (int)Math.Round(scores.Average());
            int errors = checks.Count(static c => c.Outcome == CheckOutcome.Error);
            int warnings = checks.Count(static c => c.Outcome == CheckOutcome.Warning);
            bool incomplete = checks.Any(static c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete);
            string status = errors > 0 ? "Errors" : warnings > 0 ? "Needs attention" : incomplete ? "Incomplete"
                : score.HasValue ? "Passing" : "Informational";
            WriteRow(sheet, ++row, Wording.AreaLabel(area), status, (object?)score ?? "Not scored", checks.Count,
                checks.Count(static c => c.Outcome is CheckOutcome.Pass or CheckOutcome.Info), checks.Count(Wording.NeedsAttention),
                Wording.AreaNote(report, checks));
            sheet.CellFontColor(row, 2, errors > 0 ? High : warnings > 0 ? Elevated : incomplete ? Muted : score.HasValue ? Good : Informational);
            if (!score.HasValue || score == 0) { sheet.CellFontColor(row, 3, Muted); }
            for (int column = 4; column <= 6; column++) {
                // Counts use ordinary ink; zero never implies a green outcome.
                if ((column == 5 && !checks.Any(static c => c.Outcome is CheckOutcome.Pass or CheckOutcome.Info))
                    || (column == 6 && !checks.Any(Wording.NeedsAttention))) { sheet.CellFontColor(row, column, Muted); }
            }
            sheet.CellFontColor(row, 7, Muted);
        }
        FinishSheet(sheet, header, row, 7, (1, 28), (7, 44));
    }

    private static void WriteActions(ExcelSheet sheet, DomainAssessmentReport report, AssessmentExcelOptions options) {
        WriteRow(sheet, 1, "Do these first");
        sheet.CellBold(1, 1);
        sheet.CellFontSize(1, 1, 10.5);
        const int header = 3;
        WriteHeader(sheet, header, "Outcome", "Check", "Domain", "Area", "Finding", "Source");
        var actions = Wording.DoFirst(report).ToList();
        int row = header;
        foreach (var action in actions.Take(options.FixFirstCount)) {
            CheckAssessment check = action.Check;
            WriteRow(sheet, ++row, Wording.OutcomeLabel(check.Outcome), check.Title, action.Domain.Domain,
                Wording.AreaLabel(check.Area), Wording.DoFirstMessage(check), Wording.DoFirstSource(check));
            sheet.CellFontColor(row, 1, OutcomeColor(check.Outcome));
            sheet.CellFontName(row, 3, "Consolas");
        }
        FinishSheet(sheet, header, row, 6, (1, 30), (5, 40), (6, 64));
        if (actions.Count == 0) {
            WriteRow(sheet, row + 2, "Nothing needs attention.");
        } else if (actions.Count > options.FixFirstCount) {
            WriteRow(sheet, row + 2, "First " + options.FixFirstCount.ToString(CultureInfo.InvariantCulture) + " of "
                + actions.Count.ToString(CultureInfo.InvariantCulture) + " actions shown; all checks and findings are in Checks and Findings.");
            sheet.CellFontColor(row + 2, 1, Muted);
        }
        sheet.AutoFitRows();
    }
}
