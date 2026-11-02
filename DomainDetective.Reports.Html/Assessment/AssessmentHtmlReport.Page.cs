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
    public static Page BuildPage(DomainAssessmentReport report, ThemeMode mode = ThemeMode.System) {
        if (report == null) throw new ArgumentNullException(nameof(report));
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
                overview.Headline(attention.Length == 0 ? "The collected checks are clear" : "Needs attention: " + string.Join(", ", attention.Select(c => c.Check.Title)),
                    string.Join(" ", attention.Select(c => c.Check.Summary ?? c.Check.Description).Where(value => !string.IsNullOrWhiteSpace(value))));
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
                foreach (var item in checks.Where(c => c.Domain == domain)) tab.Section(item.Check.Title, section => {
                    section.Text(item.Check.Summary ?? item.Check.Description ?? ResultLabel(item.Check.Outcome));
                    if (item.Check.Description != null && item.Check.Description != item.Check.Summary) section.Text(item.Check.Description);
                    if (item.Check.LongTitle != null) section.Text(item.Check.LongTitle);
                    section.Facts(new Fact { Label = "Result", Value = ResultLabel(item.Check.Outcome), Tone = ResultTone(item.Check.Outcome) },
                        new Fact { Label = "Evidence", Value = item.Check.EvidenceComplete ? "Collected" : "Incomplete" },
                        new Fact { Label = "Score", Value = item.Check.Scored ? item.Check.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not established" : "Not scored" });
                    if (item.Check.Metrics.Count > 0) section.Facts(item.Check.Metrics.Select(metric => new Fact { Label = metric.Label,
                        Value = metric.Value + (metric.Note == null ? string.Empty : " · " + metric.Note), Tone = metric.State switch {
                            MetricState.Good => Tone.Good, MetricState.Warning => Tone.Warning, MetricState.Error => Tone.Bad, _ => Tone.Neutral
                        } }).ToArray());
                    foreach (var positive in item.Check.Positives) section.Text(positive);
                    foreach (var highlight in item.Check.Highlights) section.Text(highlight);
                    if (item.Check.Facts.Count > 0) section.Facts(item.Check.Facts.Select(f => new Fact { Label = f.Label, Value = f.Value }).ToArray());
                    if (item.Check.Findings.Count > 0) section.StatusList(item.Check.Findings.Select(f => new LiveStatus {
                        Name = f.Target ?? item.Check.Title, Status = f.Message, Detail = f.Code,
                        Tone = f.Severity switch { AssessmentSeverity.Error => Tone.Bad, AssessmentSeverity.Warning => Tone.Warning, _ => Tone.Neutral } }).ToArray());
                    foreach (var recommendation in item.Check.Recommendations) section.Panel(recommendation.Title, panel => {
                        if (recommendation.Why != null) panel.Text(recommendation.Why);
                        if (recommendation.How != null) panel.Text(recommendation.How);
                        if (recommendation.Verify != null) panel.Text("Verify: " + recommendation.Verify);
                        if (recommendation.Impact != null) panel.Text("Impact: " + recommendation.Impact);
                        if (recommendation.Effort != null) panel.Text("Effort: " + recommendation.Effort);
                        foreach (var link in recommendation.Links) {
                            if (IsWebLink(link)) panel.Link("Reference", link); else panel.Text(link);
                        }
                    });
                    if (item.Check.Remediation != null) section.Panel("Remediation", panel => panel.Text(item.Check.Remediation));
                    if (item.Check.Narrative is { } narrative) section.Deferred("Detailed guidance", detail => {
                        if (!string.IsNullOrWhiteSpace(narrative.Introduction)) detail.Text(narrative.Introduction);
                        if (!string.IsNullOrWhiteSpace(narrative.WhyItMatters)) detail.Panel("Why it matters", panel => panel.Text(narrative.WhyItMatters));
                        foreach (var value in narrative.Highlights.Concat(narrative.Details).Concat(narrative.Positives).Concat(narrative.Negatives)) detail.Text(value);
                        foreach (var value in narrative.Remediations) detail.Panel("Suggested action", panel => panel.Text(value));
                        foreach (var reference in narrative.References) {
                            if (IsWebLink(reference)) detail.Link("Reference", reference); else detail.Text(reference);
                        }
                    });
                    if (item.Check.Evidence.Count > 0) section.Deferred("Supporting evidence", evidence => {
                        foreach (var block in item.Check.Evidence) evidence.Panel(block.Title, panel => {
                            if (block.Text != null) panel.Text(block.Text);
                            foreach (var value in block.Items) panel.Text(value);
                            if (block.Columns.Count > 0) panel.Table(block.Rows, columns => {
                                for (int index = 0; index < block.Columns.Count; index++) {
                                    int cell = index; columns.Column(block.Columns[index], row => cell < row.Count ? row[cell] : string.Empty);
                                }
                            }, block.Title);
                            if (block.Omitted > 0) panel.Text(block.Omitted + " entries omitted by the evidence collector.");
                        });
                    });
                    foreach (var reference in item.Check.References) {
                        if (IsWebLink(reference)) section.Link("Technical reference", reference); else section.Text(reference);
                    }
                }).Id(item.Anchor);
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
