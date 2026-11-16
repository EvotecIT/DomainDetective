using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

/// <summary>Writes a workbook from the same assessment used by the HTML report.</summary>
public static partial class AssessmentExcelReport {
    private const string EvidenceSheet = "Evidence";

    /// <summary>Writes summary, actions, checks, findings, evidence and (when present) risk profile worksheets.</summary>
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
        workbook.ApplyTheme(Theme);
        // Tab order is fixed up front; evidence is written first so checks can link to their rows.
        ExcelSheet summary = workbook.AddSheet("Summary");
        ExcelSheet actions = workbook.AddSheet("Do these first");
        ExcelSheet checks = workbook.AddSheet("Checks");
        ExcelSheet findings = workbook.AddSheet("Findings");
        ExcelSheet evidence = workbook.AddSheet(EvidenceSheet);
        List<DomainAssessment> profiled = Wording.RiskOrder(report).ToList();
        ExcelSheet? risk = profiled.Count > 0 ? workbook.AddSheet("Risk profile") : null;
        Dictionary<CheckAssessment, int> evidenceRows = WriteEvidence(evidence, report);
        WriteSummary(summary, report, options);
        WriteActions(actions, report, options);
        WriteChecks(checks, report, evidenceRows);
        WriteFindings(findings, report, options);
        if (risk != null) { WriteRiskProfiles(risk, profiled); }
        workbook.Save();
    }

    private static bool Several(DomainAssessmentReport report) => report.Domains.Count != 1;

    private static string Scope(DomainAssessmentReport report) => report.Domains.Count == 1
        ? report.Domains[0].Domain : Wording.Plural(report.Domains.Count, "domain");

    private static void WriteSummary(ExcelSheet sheet, DomainAssessmentReport report, AssessmentExcelOptions options) {
        List<CheckAssessment> all = report.Domains.SelectMany(static d => d.Checks).ToList();
        Title(sheet, "Domain assessment · " + Scope(report), "Generated " + Wording.FormatTime(report.GeneratedAtUtc) + " · "
            + Wording.Plural(all.Count, "check") + " in " + Wording.Plural(all.Select(static c => c.Area).Distinct().Count(), "area"));
        WriteCell(sheet, 4, 1, Wording.ReportVerdict(report)).SetBold().SetFontSize(OfficeLength.Points(11));
        WriteCell(sheet, 5, 1, Wording.ReportVerdictDetail(report)).SetColor(OfficeColor.Parse(Muted));

        // Value tiles: a label row and a large value row, one cell each, so nothing is merged.
        int errors = all.Count(static c => c.Outcome == CheckOutcome.Error);
        int attention = all.Count(Wording.NeedsAttention);
        int incomplete = all.Count(static c => !c.EvidenceComplete);
        var tiles = new List<(string Label, string Value, string Tone, string? Note)> {
            ("Grade · score", OfficeScoreText.Graded(report.Grade, report.Score, null), ScoreTone(report.Score),
                OfficeScoreText.Partial(report.Coverage) ? OfficeScoreText.Percent(report.Coverage!.Value) + " of checks judged" : null),
            ("Needs attention", Text(attention), errors > 0 ? High : attention > 0 ? Elevated : Muted, null),
            ("Errors", Text(errors), errors > 0 ? High : Muted, null),
            (Wording.OutcomeLabel(CheckOutcome.Incomplete), Text(incomplete), Muted, null)
        };
        if (report.Domains.Count == 1 && report.Domains[0].RiskProfile is { } riskProfile) {
            tiles.Add(("Risk", Wording.RiskValue(riskProfile), RiskColor(riskProfile), null));
            tiles.Add(("Confidence", Wording.ConfidenceValue(riskProfile), Muted, null));
        }
        for (int index = 0; index < tiles.Count; index++) {
            int column = index + 1;
            WriteCell(sheet, 7, column, tiles[index].Label.ToUpperInvariant()).SetColor(OfficeColor.Parse(Muted)).SetFontSize(OfficeLength.Points(8)).SetBold();
            WriteCell(sheet, 8, column, tiles[index].Value).SetColor(OfficeColor.Parse(tiles[index].Tone)).SetFontSize(OfficeLength.Points(13)).SetBold();
            WriteCell(sheet, 9, column, tiles[index].Note ?? string.Empty).SetColor(OfficeColor.Parse(Muted)).SetFontSize(OfficeLength.Points(8));
            for (int band = 7; band <= 9; band++) { sheet.Cell(band, column).SetFillColor(OfficeColor.Parse(Surface)); }
            sheet.Cell(7, column).SetBorder(ExcelCellBorders.Top, ExcelBorderStyle.Medium, OfficeColor.Parse(tiles[index].Tone == Muted ? Rule : tiles[index].Tone));
        }
        sheet.SetRowHeight(8, ExcelColumnWidth.Length(OfficeLength.Points(22)));
        int row = 9;
        if (report.Domains.Count == 1 && report.Domains[0].RiskProfile is { } single) {
            WriteCell(sheet, ++row, 1, Wording.RiskVerdict(single) + (Wording.ConfidenceNote(single) is { } note ? " " + note : string.Empty))
                .SetColor(OfficeColor.Parse(Muted));
        }

        // Area table.
        row += 2;
        WriteCell(sheet, row, 1, "Area by area").SetBold().SetFontSize(OfficeLength.Points(11));
        int header = ++row;
        WriteHeader(sheet, header, "Area", "Status", "Score", "Judged", "Checks", "Passing", "Needs attention", "Notes");
        var areas = new List<(string Label, List<CheckAssessment> Checks)>();
        foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
            List<CheckAssessment> checks = all.Where(c => c.Area == area).ToList();
            if (checks.Count == 0) { continue; }
            areas.Add((Wording.AreaLabel(area), checks));
            (int? score, double? coverage) = OfficeScoreText.Area(checks);
            string tone = AreaTone(checks);
            WriteRow(sheet, ++row, Wording.AreaLabel(area), AreaStatus(checks), score, coverage, checks.Count,
                checks.Count(static c => c.Scored && c.Outcome == CheckOutcome.Pass), checks.Count(Wording.NeedsAttention),
                Wording.AreaNote(report, checks) + ReputationRisk(report, area));
            sheet.Cell(row, 1).SetBold();
            Tone(sheet, row, 2, tone);
            if (coverage.HasValue) { sheet.Cell(row, 4).SetNumberFormat("0%"); }
            if (coverage is < 1) { sheet.Cell(row, 4).SetColor(OfficeColor.Parse(Muted)); }
            if (!checks.Any(Wording.NeedsAttention)) { sheet.Cell(row, 7).SetColor(OfficeColor.Parse(Muted)); }
            sheet.Cell(row, 8).SetColor(OfficeColor.Parse(Muted));
        }
        int lastArea = row;
        ScoreBars(sheet, "C", header + 1, lastArea);
        Center(sheet, header, lastArea, 4, 5, 6, 7);
        Table(sheet, "Areas", header, lastArea, 8, 24, 20, 16, 20, 20, 20, 16, 64);
        Wrap(sheet, header + 1, lastArea, 8);
        WriteCell(sheet, ++row, 1, "Score is blank where nothing in the area could be judged. Judged is the share of the scored weight with complete evidence.")
            .SetColor(OfficeColor.Parse(Muted)).SetFontSize(OfficeLength.Points(8));

        // Several domains: one row per domain with its grade and risk.
        if (Several(report) && report.Domains.Count > 0) {
            row += 2;
            WriteCell(sheet, row, 1, "Domains").SetBold().SetFontSize(OfficeLength.Points(11));
            int domainHeader = ++row;
            WriteHeader(sheet, domainHeader, "Domain", "Grade", "Score", "Judged", "Errors", "Warnings", "Risk", "Verdict");
            foreach (DomainAssessment domain in report.Domains) {
                DomainRiskProfile? profile = domain.RiskProfile;
                WriteRow(sheet, ++row, domain.Domain, domain.Score.HasValue ? domain.Grade : "Not scored", domain.Score, domain.Coverage,
                    domain.ErrorChecks, domain.WarningChecks, profile == null ? null : Wording.RiskValue(profile), Wording.DomainVerdict(domain));
                sheet.Cell(row, 1).SetFontFamily(Mono);
                sheet.Cell(row, 2).SetColor(OfficeColor.Parse(ScoreTone(domain.Score))).SetBold();
                if (domain.Coverage.HasValue) { sheet.Cell(row, 4).SetNumberFormat("0%"); }
                if (domain.ErrorChecks > 0) { Tone(sheet, row, 5, High); } else { sheet.Cell(row, 5).SetColor(OfficeColor.Parse(Muted)); }
                if (domain.WarningChecks > 0) { Tone(sheet, row, 6, Elevated); } else { sheet.Cell(row, 6).SetColor(OfficeColor.Parse(Muted)); }
                if (profile != null) { sheet.Cell(row, 7).SetColor(OfficeColor.Parse(RiskColor(profile))); }
                sheet.Cell(row, 8).SetColor(OfficeColor.Parse(Muted));
            }
            ScoreBars(sheet, "C", domainHeader + 1, row);
            Center(sheet, domainHeader, row, 4, 5, 6);
            Table(sheet, "Domains", domainHeader, row, 8);
            Wrap(sheet, domainHeader + 1, row, 8);
        }

        // Top actions, so the dashboard answers "what now" without switching sheets.
        var top = Wording.DoFirstGroups(report).Take(Math.Min(5, options.FixFirstCount)).ToList();
        row += 2;
        WriteCell(sheet, row, 1, "Do these first").SetBold().SetFontSize(OfficeLength.Points(11));
        if (top.Count == 0) {
            WriteCell(sheet, ++row, 1, "Nothing needs attention.").SetColor(OfficeColor.Parse(Muted));
        } else {
            foreach (var action in top) {
                WriteCell(sheet, ++row, 1, action.Check.Title).SetBold();
                WriteCell(sheet, row, 2, Wording.OutcomeLabel(action.Check.Outcome));
                Tone(sheet, row, 2, OutcomeColor(action.Check.Outcome));
                // The finding overflows across the empty cells to its right.
                WriteCell(sheet, row, 3, Wording.DoFirstMessage(action.Check) + (Several(report) ? " (" + action.AffectedDomains + ")" : string.Empty));
            }
            WriteCell(sheet, ++row, 1, "The full list, one row per domain and check, is on the Do these first sheet.")
                .SetColor(OfficeColor.Parse(Muted)).SetFontSize(OfficeLength.Points(8));
        }

        // Outcome counts, overall and per area, with a doughnut of the overall split beside them.
        row += 2;
        WriteCell(sheet, row, 1, "Checks by outcome").SetBold().SetFontSize(OfficeLength.Points(11));
        int outcomeHeader = ++row;
        CheckOutcome[] order = { CheckOutcome.Pass, CheckOutcome.Warning, CheckOutcome.Error, CheckOutcome.Incomplete, CheckOutcome.Info };
        WriteHeader(sheet, outcomeHeader, new[] { "Outcome", "Checks" }.Concat(areas.Select(static a => a.Label)).ToArray());
        foreach (CheckOutcome outcome in order) {
            var values = new List<object?> { Wording.OutcomeLabel(outcome), all.Count(c => c.Outcome == outcome) };
            values.AddRange(areas.Select(a => (object?)a.Checks.Count(c => c.Outcome == outcome)));
            WriteRow(sheet, ++row, values.ToArray());
            Tone(sheet, row, 1, OutcomeColor(outcome));
            for (int column = 2; column <= areas.Count + 2; column++) {
                if (values[column - 1] is 0) { sheet.Cell(row, column).SetColor(OfficeColor.Parse(Muted)); }
            }
        }
        Table(sheet, "Outcomes", outcomeHeader, row, areas.Count + 2);
        if (all.Count > 0) {
            ExcelChart chart = sheet.AddChart(OfficeIMO.OfficeChartType.Doughnut, "A" + Text(outcomeHeader) + ":B" + Text(row), new ExcelChartOptions {
                Row = row + 2, Column = 1, Title = "Checks by outcome",
                Width = OfficeLength.Centimeters(11), Height = OfficeLength.Centimeters(7)
            });
            for (int point = 0; point < order.Length; point++) {
                chart.SetDataPointFillColor(0, (uint)point, OfficeColor.Parse(OutcomeColor(order[point]) == Muted ? "A3AAB1" : OutcomeColor(order[point])));
            }
            chart.SetLegend(OfficeIMO.Drawing.OfficeChartLegendPosition.Right);
        }
        Paper(sheet, 0, 0, Tabs[0]);
        sheet.View.ShowGridlines = false;
    }

    private static void WriteActions(ExcelSheet sheet, DomainAssessmentReport report, AssessmentExcelOptions options) {
        bool several = Several(report);
        var actions = Wording.DoFirst(report).ToList();
        Title(sheet, "Do these first · " + Scope(report), actions.Count > options.FixFirstCount
            ? "First " + Text(options.FixFirstCount) + " of " + Text(actions.Count) + " actions shown; every check and finding is on the Checks and Findings sheets."
            : "In the order to fix them: security exposure first, then errors before warnings.");
        const int header = 4;
        WriteHeader(sheet, header, several
            ? new[] { "Domain", "Check", "Outcome", "Area", "Finding", "Source" }
            : new[] { "Check", "Outcome", "Area", "Finding", "Source" });
        int row = header;
        int offset = several ? 1 : 0;
        foreach (var action in actions.Take(options.FixFirstCount)) {
            CheckAssessment check = action.Check;
            WriteRow(sheet, ++row, Row(several, action.Domain.Domain, check.Title, Wording.OutcomeLabel(check.Outcome),
                Wording.AreaLabel(check.Area), Wording.DoFirstMessage(check), Wording.DoFirstSource(check)));
            if (several) { sheet.Cell(row, 1).SetFontFamily(Mono); }
            sheet.Cell(row, 1 + offset).SetBold();
            Tone(sheet, row, 2 + offset, OutcomeColor(check.Outcome));
            sheet.Cell(row, 5 + offset).SetColor(OfficeColor.Parse(Muted));
        }
        if (actions.Count == 0) { WriteCell(sheet, ++row, 1 + offset, "Nothing needs attention."); }
        Table(sheet, "Actions", header, row, 5 + offset, several ? new double[] { 26, 20, 12, 10, 80, 28 } : new double[] { 20, 12, 10, 80, 28 });
        Wrap(sheet, header + 1, row, 4 + offset);
        Paper(sheet, header, several ? 2 : 1, Tabs[0]);
    }

    /// <summary>
    /// Reputation is judged by the risk profile rather than a configuration score, so its area note carries the risk
    /// for a one-domain report.
    /// </summary>
    private static string ReputationRisk(DomainAssessmentReport report, AnalysisArea area) =>
        area == AnalysisArea.Reputation && report.Domains.Count == 1 && report.Domains[0].RiskProfile is { } profile
            ? " Risk: " + Wording.RiskValue(profile) + "." : string.Empty;

    private static string AreaStatus(List<CheckAssessment> checks) => checks.Any(static c => c.Outcome == CheckOutcome.Error) ? "Errors"
        : checks.Any(static c => c.Outcome == CheckOutcome.Warning) ? "Needs attention"
        : checks.Any(static c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) ? Wording.OutcomeLabel(CheckOutcome.Incomplete)
        : checks.Any(static c => c.Scored) ? "Passing" : "Informational";

    private static string AreaTone(List<CheckAssessment> checks) => checks.Any(static c => c.Outcome == CheckOutcome.Error) ? High
        : checks.Any(static c => c.Outcome == CheckOutcome.Warning) ? Elevated
        : checks.Any(static c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) ? Muted
        : checks.Any(static c => c.Scored) ? Good : Informational;

    private static string ScoreTone(int? score) => score switch {
        null => Muted,
        >= 90 => Good,
        >= 75 => Elevated,
        _ => High
    };
}
