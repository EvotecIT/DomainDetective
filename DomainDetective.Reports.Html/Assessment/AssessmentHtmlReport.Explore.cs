using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using static DomainDetective.Reports.AssessmentReportWording;
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
        /// <summary>The check's target and the finding's position in it: stable for one report.</summary>
        public string Id { get; set; } = string.Empty;
    }

    /// <summary>
    /// Every check and every finding across the report as filterable tables. A row opens its check in the result
    /// drawer; previous and next walk the rows as filtered, so a reader can go through "every DMARC warning" or "every
    /// finding on one name server" without leaving the table.
    /// </summary>
    private static void RenderExplore(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids, AssessmentHtmlOptions options) {
        var actions = DoFirstGroups(report).ToList();
        var actionKeys = actions.Select((_, index) => "priority-" + index.ToString(CultureInfo.InvariantCulture)).ToArray();
        var actionByTarget = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int index = 0; index < actions.Count; index++) {
            foreach (var member in actions[index].Members) {
                actionByTarget[ids.Check(member.Domain, member.Check)] = actionKeys[index];
            }
        }
        List<CheckRow> checks = report.Domains
            .SelectMany(d => d.Checks.Select(c => new CheckRow { Domain = d, Check = c, Target = ids.Check(d, c) }))
            .ToList();
        List<FindingRow> findings = checks
            .SelectMany(row => row.Check.Findings.Where(f => options.ShowInfoFindings || f.Severity != AssessmentSeverity.Info)
                .Select((f, i) => new FindingRow { Owner = row, Finding = f, Id = row.Target + "/" + i.ToString(CultureInfo.InvariantCulture) }))
            .ToList();

        ReportDataset checkData = ReportDataset.Create("checks", checks, b => b
            .Title("Checks")
            .Text("target", "Target", static r => r.Target, c => c.Key().Hidden())
            // Readable chips keep exact group keys, even when different findings share a display label.
            .Category("action", "Action", r => actionByTarget.TryGetValue(r.Target, out string? key) ? key : null, c => {
                c.Hidden();
                for (int index = 0; index < actions.Count; index++) {
                    var action = actions[index];
                    int domains = action.Members.Select(member => member.Domain.Domain).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                    c.ValueLabel(actionKeys[index], action.Check.Title + " on " + Plural(domains, "domain"));
                }
            })
            // The check names the row and its outcome stays beside it on a phone; domain and area give way first.
            .Category("check", "Check", static r => r.Check.Title, c => c.RowHeader())
            .Category("outcome", "Outcome", static r => OutcomeLabel(r.Check.Outcome), c => c.ResponsivePriority(1)
                .Tone(Severity.High, "Error").Tone(Severity.Elevated, "Warning").Tone(Severity.Skipped, "Incomplete").Tone(Severity.Good, "Pass").Tone(Severity.Informational, "Info"))
            .Category("domain", "Domain", static r => r.Domain.Domain, c => c.ResponsivePriority(2))
            .Category("area", "Area", static r => AreaLabel(r.Check.Area))
            .Text("headline", "Key number", static r => Headline(r.Check) is { } m ? m.Label + ": " + m.Value : null)
            .Number("score", "Score", static r => r.Check.Scored ? r.Check.Score : null)
            .Number("errors", "Errors", static r => r.Check.ErrorCount)
            .Number("warnings", "Warnings", static r => r.Check.WarningCount)
            .Text("topFinding", "Top finding", static r => r.Check.Findings.FirstOrDefault(static f => f.Severity != AssessmentSeverity.Info)?.Message, c => c.LongText())
            .Text("keyNumbers", "Key numbers", static r => r.Check.Metrics.Count == 0 ? null : string.Join(" · ", r.Check.Metrics.Select(static m => m.Label + ": " + m.Value)), c => c.LongText().Hidden())
            .Text("summary", "Summary", static r => r.Check.Summary ?? r.Check.Description, c => c.LongText().Hidden()));

        ReportDataset findingData = ReportDataset.Create("findings", findings, b => b
            .Title("Findings")
            .Text("id", "Finding ID", static r => r.Id, c => c.Key().Hidden())
            .Text("target", "Target", static r => r.Owner.Target, c => c.Hidden())
            .Category("check", "Check", static r => r.Owner.Check.Title, c => c.RowHeader())
            .Category("severity", "Severity", static r => FindingLabel(r.Finding), c => {
                c.ResponsivePriority(1).Tone(Severity.High, "Error").Tone(Severity.Elevated, "Warning").Tone(Severity.Informational, "Info");
                if (findings.Any(f => f.Finding.IsEvidenceGap)) { c.Tone(Severity.Skipped, "Incomplete"); }
            })
            .Category("domain", "Domain", static r => r.Owner.Domain.Domain, c => c.ResponsivePriority(2))
            .Text("message", "Finding", static r => r.Finding.Message, c => c.LongText())
            .Text("where", "Where", static r => string.Equals(r.Finding.Target, r.Owner.Domain.Domain, StringComparison.OrdinalIgnoreCase) ? null : r.Finding.Target, c => c.Monospace())
            .Category("code", "Code", static r => r.Finding.Code, c => c.Monospace())
            .Category("area", "Area", static r => AreaLabel(r.Owner.Check.Area)));

        int attention = checks.Count(static r => NeedsAttention(r.Check));
        section.AssessmentViews(views => {
            views.View("explore-checks", "Checks", view => view.DataExplorer(checkData, explorer => {
                explorer.Key(ChecksExplorer).Title("Checks")
                    .Description("One row per check and domain with its key number. Open a row for the full result; previous and next follow the rows below.");
                if (attention > 0) explorer.AddView("Needs attention", v => v
                    .Where("outcome", ReportFilterOperator.In, "Error", "Warning", "Incomplete").OrderBy("score").OrderBy("domain").Default());
                explorer.AddView("All checks", v => v.OrderBy("domain"))
                    .AddView("By check", v => v.OrderBy("check").OrderBy("domain"))
                    .QuickFilters("outcome", "area")
                    .Settings(s => s.RowTarget("target").Drawer(true, "check", "domain").Exports(DataExplorerExports.Csv));
                for (int index = 0; index < actions.Count; index++) {
                    var action = actions[index];
                    if (action.Members.Count < 2) { continue; }
                    explorer.AddShortcut(actionKeys[index], shortcut => shortcut
                        .View("All checks").Where("action", ReportFilterOperator.EqualTo, actionKeys[index]));
                }
            }));
            views.View("explore-findings", "Findings", view => view.DataExplorer(findingData, explorer => {
                explorer.Key(FindingsExplorer).Title("Findings")
                    .Description("Every warning and error each check raised, with where it was seen. Open a row for the check it belongs to.")
                    .AddView("Errors and warnings", v => v.Where("severity", ReportFilterOperator.In, "Error", "Warning").Default())
                    .AddView("All findings")
                    .QuickFilters("severity", "area")
                    .Settings(s => s.RowTarget("target").Drawer(true, "check", "domain").Exports(DataExplorerExports.Csv));
            }));
        });
    }

}
