using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

public static partial class AssessmentHtmlReport {
    private const string ChecksExplorer = "dd-checks";
    private const string FindingsExplorer = "dd-findings";

    private sealed class CheckRow {
        public DomainAssessment Domain { get; set; } = null!;
        public CheckAssessment Check { get; set; } = null!;
        public string Target { get; set; } = string.Empty;
    }

    private sealed class FindingRow {
        public CheckRow Owner { get; set; } = null!;
        public CheckFinding Finding { get; set; } = null!;
    }

    /// <summary>
    /// Every check and every finding across the report as filterable tables. A row opens its check in the result
    /// drawer; previous and next walk the rows as filtered, so a reader can go through "every DMARC warning" or "every
    /// finding on one name server" without leaving the table.
    /// </summary>
    private static void RenderExplore(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        List<CheckRow> checks = report.Domains
            .SelectMany(d => d.Checks.Select(c => new CheckRow { Domain = d, Check = c, Target = ids.Check(d, c) }))
            .ToList();
        List<FindingRow> findings = checks
            .SelectMany(static row => row.Check.Findings.Select(f => new FindingRow { Owner = row, Finding = f }))
            .ToList();

        ReportDataset checkData = ReportDataset.Create("checks", checks, b => b
            .Title("Checks")
            .Text("target", "Target", static r => r.Target, c => c.Hidden())
            .Category("domain", "Domain", static r => r.Domain.Domain, c => c.Key())
            .Category("area", "Area", static r => AreaLabel(r.Check.Area))
            .Category("check", "Check", static r => r.Check.Title)
            .Category("outcome", "Outcome", static r => OutcomeLabel(r.Check.Outcome), c => c
                .Tone(Severity.High, "Error").Tone(Severity.Elevated, "Warning").Tone(Severity.Good, "Pass").Tone(Severity.Informational, "Info"))
            .Text("headline", "Key number", static r => Headline(r.Check) is { } m ? m.Label + ": " + m.Value : null)
            .Number("score", "Score", static r => r.Check.Scored ? r.Check.Score : null)
            .Number("errors", "Errors", static r => r.Check.ErrorCount)
            .Number("warnings", "Warnings", static r => r.Check.WarningCount)
            .Text("topFinding", "Top finding", static r => r.Check.Findings.FirstOrDefault(static f => f.Severity != AssessmentSeverity.Info)?.Message, c => c.LongText())
            .Text("keyNumbers", "Key numbers", static r => r.Check.Metrics.Count == 0 ? null : string.Join(" · ", r.Check.Metrics.Select(static m => m.Label + ": " + m.Value)), c => c.LongText().Hidden())
            .Text("summary", "Summary", static r => r.Check.Summary ?? r.Check.Description, c => c.LongText().Hidden()));

        ReportDataset findingData = ReportDataset.Create("findings", findings, b => b
            .Title("Findings")
            .Text("target", "Target", static r => r.Owner.Target, c => c.Hidden())
            .Category("severity", "Severity", static r => FindingSeverityLabel(r.Finding.Severity), c => c
                .Tone(Severity.High, "Error").Tone(Severity.Elevated, "Warning").Tone(Severity.Informational, "Info"))
            .Category("domain", "Domain", static r => r.Owner.Domain.Domain)
            .Category("check", "Check", static r => r.Owner.Check.Title)
            .Text("message", "Finding", static r => r.Finding.Message, c => c.LongText())
            .Text("where", "Where", static r => string.Equals(r.Finding.Target, r.Owner.Domain.Domain, StringComparison.OrdinalIgnoreCase) ? null : r.Finding.Target, c => c.Monospace())
            .Category("code", "Code", static r => r.Finding.Code, c => c.Monospace())
            .Category("area", "Area", static r => AreaLabel(r.Owner.Check.Area)));

        int attention = checks.Count(static r => r.Check.Outcome is CheckOutcome.Error or CheckOutcome.Warning);
        section.AssessmentViews(views => {
            views.View("explore-checks", "Checks", view => view.DataExplorer(checkData, explorer => {
                explorer.Key(ChecksExplorer).Title("Checks")
                    .Description("One row per check and domain with its key number. Open a row for the full result; previous and next follow the rows below.");
                if (attention > 0) explorer.AddView("Needs attention", v => v
                    .Where("outcome", ReportFilterOperator.In, "Error", "Warning").OrderBy("score").OrderBy("domain").Default());
                explorer.AddView("All checks", v => v.OrderBy("domain"))
                    .AddView("By check", v => v.OrderBy("check").OrderBy("domain"))
                    .QuickFilters("outcome", "area", "check", "domain")
                    .Settings(s => s.RowTarget("target").Drawer(true, "check", "domain").Exports(DataExplorerExports.Csv));
            }));
            views.View("explore-findings", "Findings", view => view.DataExplorer(findingData, explorer => {
                explorer.Key(FindingsExplorer).Title("Findings")
                    .Description("Every warning and error each check raised, with where it was seen. Open a row for the check it belongs to.")
                    .AddView("Errors and warnings", v => v.Where("severity", ReportFilterOperator.In, "Error", "Warning").Default())
                    .AddView("All findings")
                    .QuickFilters("severity", "check", "domain")
                    .Settings(s => s.RowTarget("target").Drawer(true, "check", "domain").Exports(DataExplorerExports.Csv));
            }));
        });
    }

    // The number that says most about a check: a missing record first, otherwise the control's headline metric.
    private static CheckMetric? Headline(CheckAssessment check) {
        if (check.Metrics.Count == 0) return null;
        if (check.Metrics[0].Label == "Record") return check.Metrics[0];
        string? preferred = Controls.FirstOrDefault(c => c.Key == check.Key).Headline;
        return (string.IsNullOrEmpty(preferred) ? null : check.Metrics.FirstOrDefault(m => m.Label == preferred)) ?? check.Metrics[0];
    }

    private static string FindingSeverityLabel(AssessmentSeverity severity) => severity switch {
        AssessmentSeverity.Error => "Error",
        AssessmentSeverity.Warning => "Warning",
        _ => "Info"
    };
}
