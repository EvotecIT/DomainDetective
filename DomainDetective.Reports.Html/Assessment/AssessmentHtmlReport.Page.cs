using System;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using Hfx = HtmlForgeX.Html;
using CanopyX;

namespace DomainDetective.Reports.Html;

public static partial class AssessmentHtmlReport {
    /// <summary>Projects the format-independent assessment through the typed page API.</summary>
    public static Page BuildPage(DomainAssessmentReport report, ThemeMode mode = ThemeMode.System, DisplayLabels? findingLabels = null) {
        if (report == null) throw new ArgumentNullException(nameof(report));
        findingLabels ??= AssessmentPageLabels.Findings();
        var checks = report.Domains.SelectMany((domain, domainIndex) => domain.Checks.Select((check, checkIndex) =>
            new { Domain = domain, Check = check, Anchor = "domain-" + domainIndex + "-check-" + checkIndex }))
            .OrderBy(row => row.Check.Outcome == CheckOutcome.Error ? 0 : row.Check.Outcome == CheckOutcome.Warning ? 1 : 2).ToArray();
        var dataset = ReportDataset.Create("domain-checks", checks, columns => columns.Title("Every check")
            .Text("id", "Check identity", row => row.Anchor, column => column.Key().Hidden())
            .Text("domain", "Domain", row => row.Domain.Domain)
            .Text("check", "Check", row => row.Check.Title)
            .Category("result", "Result", row => ResultLabel(row.Check.Outcome), column => column
                .Tone("Failed", ReportStatus.Fail(ReportSeverity.Critical)).Tone("Review", ReportStatus.Fail(ReportSeverity.Medium)).Tone("Passed", ReportStatus.Pass))
            .Text("summary", "Summary", row => row.Check.Summary ?? row.Check.Description ?? string.Empty));
        var explorer = ReportGrid.FromDataset(dataset, "assessment-checks");
        explorer.Columns.First(column => column.Id == "result").Ordering = new CanopyGridOrdering(categories: new[] { "Failed", "Review", "Not established", "Information", "Passed" });
        explorer.Query = new CanopyGridQuery(explorer.Id);
        explorer.Query.Sort.Add(new CanopyGridSort("result"));
        explorer.Reporting = new CanopyGridReporting { HeaderFilters = true, FilterGroups = true };
        return Hfx.Page(report.Title, page => {
            page.Theme(AssessmentPageTheme.Create()).Mode(mode).Subtitle("DomainDetective · " + PageTime.Utc(report.GeneratedAtUtc));
            page.Tab("Overview", overview => {
                var attention = checks.Where(c => c.Check.Outcome is CheckOutcome.Error or CheckOutcome.Warning).ToArray();
                overview.Headline(AssessmentPageLabels.AttentionHeadline(attention.Select(c => c.Check).ToArray()));
                overview.Kpis(new KpiTile { Label = "Overall score", Value = report.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not scored",
                    Detail = "Grade " + report.Grade + " · " + AssessmentPageLabels.Checks(attention.Length) + " to review · " + AssessmentPageLabels.Domains(report.Domains.Count), Lead = true });
                overview.Panel("Findings", panel => panel.AttentionQueue(attention
                    .Select(c => new AttentionItem { Title = c.Check.Title + " · " + c.Domain.Domain, Detail = c.Check.Summary ?? c.Check.Description ?? ResultLabel(c.Check.Outcome),
                        Tone = ResultTone(c.Check.Outcome), Action = new NextStep { Label = "Review evidence", Target = "#" + c.Anchor } }).ToArray()));
                overview.Columns(columns => {
                    columns.Card("Domains", card => card.StatusList(report.Domains.Select(d => new LiveStatus { Name = d.Domain,
                        Status = d.ErrorChecks > 0 ? "Needs attention" : d.WarningChecks > 0 ? "Review recommended" : "Healthy",
                        Detail = d.PassedChecks + " passed · " + AssessmentPageLabels.Warnings(d.WarningChecks) + " · " + AssessmentPageLabels.Errors(d.ErrorChecks),
                        Tone = d.ErrorChecks > 0 ? Tone.Bad : d.WarningChecks > 0 ? Tone.Warning : Tone.Good }).ToArray()));
                    columns.Card("Assessment coverage", card => card.Facts(new Fact { Label = "Collected", Value = AssessmentPageLabels.Checks(checks.Length) + " across " + AssessmentPageLabels.Domains(report.Domains.Count) },
                        new Fact { Label = "Additional sources", Value = "Authenticated probes can add internal service evidence when access is available." }));
                });
            });
            page.Tab("Explore", tab => tab.Grid(explorer));
            foreach (var domain in report.Domains) page.Tab(domain.Domain, tab => {
                tab.EntityHeader(domain.Domain, "Domain assessment", new Fact { Label = "Grade", Value = domain.Grade },
                    new Fact { Label = "Score", Value = domain.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not scored" });
                if (domain.Areas.Count > 0) tab.Panel("Scores by area", panel => panel.Facts(domain.Areas.Select(area => new Fact {
                    Label = AreaLabel(area.Area), Value = (area.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not scored") + " · " + area.Checks + " checks · " + area.Attention + " to review"
                }).ToArray()));
                foreach (var item in checks.Where(c => c.Domain == domain))
                    tab.Section(item.Check.Title, section => RenderPageCheck(section, item.Check, findingLabels)).Id(item.Anchor);
            });
            page.Tab("About", tab => {
                tab.Facts(new Fact { Label = "Generated", Value = PageTime.Utc(report.GeneratedAtUtc) }, new Fact { Label = "Report", Value = report.Title });
                tab.Text("Results describe the evidence collected for this assessment. A missing or unscored check is not a passing result.");
                if (report.UnassignedInputs.Count > 0) tab.Panel("Inputs without a matching check", panel => {
                    foreach (var input in report.UnassignedInputs) panel.Text(input);
                });
            });
        });
    }
    private static string ResultLabel(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Pass => "Passed", CheckOutcome.Info => "Information", CheckOutcome.Warning => "Review", CheckOutcome.Error => "Failed", _ => "Not established"
    };
    private static Tone ResultTone(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Pass => Tone.Good, CheckOutcome.Warning => Tone.Warning, CheckOutcome.Error => Tone.Bad, _ => Tone.Neutral
    };
    private static bool IsWebLink(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https";
}
