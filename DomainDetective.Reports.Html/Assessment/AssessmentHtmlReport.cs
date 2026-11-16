using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using static DomainDetective.Reports.AssessmentReportWording;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

/// <summary>Options for <see cref="AssessmentHtmlReport"/>.</summary>
public sealed class AssessmentHtmlOptions {
    /// <summary>Brand shown in the report bar. Defaults to "DomainDetective".</summary>
    public string Brand { get; set; } = "DomainDetective";

    /// <summary>Optional subtitle. Defaults to the assessed domains and generation time.</summary>
    public string? Subtitle { get; set; }

    /// <summary>Initial theme. Defaults to the viewer's system preference.</summary>
    public ThemeMode Theme { get; set; } = ThemeMode.System;

    /// <summary>
    /// How scripts and styles are included. Defaults to <see cref="LibraryMode.Offline"/>, so the file opens without
    /// internet access.
    /// </summary>
    public LibraryMode LibraryMode { get; set; } = LibraryMode.Offline;

    /// <summary>Include informational findings next to warnings and errors. Defaults to false.</summary>
    public bool ShowInfoFindings { get; set; }

    /// <summary>Number of items in the summary's "Do these first" list before it expands. Defaults to 3.</summary>
    public int FixFirstCount { get; set; } = 3;
}

/// <summary>
/// Renders a <see cref="DomainAssessmentReport"/> as a single-file HTML assessment: a summary with the overall score
/// and what to fix first, a coverage matrix across domains, and one section per domain with every check, its findings,
/// evidence and guidance.
/// </summary>
public static partial class AssessmentHtmlReport {
    /// <summary>Builds the assessment from views and writes the HTML report.</summary>
    /// <param name="path">Output file path.</param>
    /// <param name="items">View objects produced by <c>DomainDetective.Views.Converters</c>.</param>
    /// <param name="assessmentOptions">Model options.</param>
    /// <param name="htmlOptions">Rendering options.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    /// <returns>The assessment the report was rendered from.</returns>
    public static DomainAssessmentReport Generate(string path, IReadOnlyList<object> items, DomainAssessmentOptions? assessmentOptions = null,
        AssessmentHtmlOptions? htmlOptions = null, bool openInBrowser = false) {
        DomainAssessmentReport report = DomainAssessmentBuilder.Build(items, assessmentOptions);
        Generate(path, report, htmlOptions, openInBrowser);
        return report;
    }

    /// <summary>Writes the HTML report for an assessment.</summary>
    /// <param name="path">Output file path.</param>
    /// <param name="report">Assessment to render.</param>
    /// <param name="options">Rendering options.</param>
    /// <param name="openInBrowser">Open the file after saving.</param>
    public static void Generate(string path, DomainAssessmentReport report, AssessmentHtmlOptions? options = null, bool openInBrowser = false) {
        if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException("An output path is required.", nameof(path));
        using Document document = Build(report, options);
        document.Save(path, openInBrowser);
    }

    /// <summary>Renders the report to an HTML string.</summary>
    /// <param name="report">Assessment to render.</param>
    /// <param name="options">Rendering options.</param>
    /// <returns>The HTML document.</returns>
    public static string Render(DomainAssessmentReport report, AssessmentHtmlOptions? options = null) {
        using Document document = Build(report, options);
        return document.ToString();
    }

    /// <summary>Builds the HtmlForgeX document for an assessment. The caller owns the returned document.</summary>
    /// <param name="report">Assessment to render.</param>
    /// <param name="options">Rendering options.</param>
    /// <returns>The document.</returns>
    public static Document Build(DomainAssessmentReport report, AssessmentHtmlOptions? options = null) {
        if (report == null) throw new ArgumentNullException(nameof(report));
        options ??= new AssessmentHtmlOptions();
        var document = new Document {
            LibraryMode = options.LibraryMode,
            ThemeMode = options.Theme
        };
        document.Head.Title = report.Title;
        document.Head.Author = options.Brand;
        document.Head.Revised = report.GeneratedAtUtc.UtcDateTime;
        document.Head.AddCssInline(TrustedCss.FromTrustedSource(DesignCss));

        var ids = new CheckIds(report);
        document.Body.AssessmentReport(shell => {
            shell.Brand(options.Brand, null)
                .Title(report.Title)
                .Subtitle(options.Subtitle ?? DefaultSubtitle(report));
            // A left menu keeps every domain visible with its grade and open checks, however many domains there are.
            shell.Settings(settings => settings.NavigationLabel("Report sections")
                .Navigation(AssessmentNavigationLayout.Sidebar, filterPlaceholder: "Filter domains"));

            shell.AddSection("Summary", section => {
                section.Key("summary").NavigationIcon(TablerIconType.LayoutDashboard).Active();
                RenderSummary(section, report, ids, options);
            });
            int attention = report.Domains.Sum(static d => d.Checks.Count(NeedsAttention));
            bool anyError = report.Domains.Any(static d => d.ErrorChecks > 0);
            shell.AddSection("Explore", section => {
                section.Key("explore").NavigationIcon(TablerIconType.ListSearch)
                    .NavigationDetail("Every check and finding")
                    .Count(attention, anyError ? Severity.High : report.Domains.Any(d => d.WarningChecks > 0) ? Severity.Elevated
                        : attention > 0 ? Severity.Skipped : Severity.Good, "checks need attention");
                RenderExplore(section, report, ids, options);
            });

            if (report.Domains.Count == 1) {
                DomainAssessment domain = report.Domains[0];
                shell.AddSection(domain.Domain, section => RenderDomain(section, domain, ids, options, report.GeneratedAtUtc));
            } else if (report.Domains.Count > 1) {
                shell.AddNavigationGroup("Domains", group => {
                    group.Key("domains").NavigationIcon(TablerIconType.World);
                    group.Settings(s => s.InlineUpTo(1).SearchAbove(8).Labels("Filter domains", "No matching domains", "Checks need attention"));
                    foreach (DomainAssessment domain in report.Domains) {
                        group.AddSection(domain.Domain, section => RenderDomain(section, domain, ids, options, report.GeneratedAtUtc));
                    }
                });
            }

            shell.AddSection("About", section => {
                section.Key("about").NavigationIcon(TablerIconType.InfoCircle);
                RenderAbout(section, report);
            });
        });
        return document;
    }

    private static string DefaultSubtitle(DomainAssessmentReport report) {
        string domains = report.Domains.Count switch {
            0 => "No domains",
            1 => report.Domains[0].Domain,
            <= 3 => string.Join(", ", report.Domains.Select(static d => d.Domain)),
            _ => $"{report.Domains.Count.ToString(CultureInfo.InvariantCulture)} domains"
        };
        return $"{domains} · generated {FormatTime(report.GeneratedAtUtc)}";
    }

    private static void RenderSummary(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids, AssessmentHtmlOptions options) {
        List<CheckAssessment> checks = report.Domains.SelectMany(static d => d.Checks).ToList();
        int errors = checks.Count(static c => c.Outcome == CheckOutcome.Error);
        int warnings = checks.Count(static c => c.Outcome == CheckOutcome.Warning);
        int passed = checks.Count(static c => c.Outcome == CheckOutcome.Pass);
        int info = checks.Count(static c => c.Outcome == CheckOutcome.Info);
        int incomplete = checks.Count(static c => !c.EvidenceComplete);

        section.AssessmentPosture(posture => {
            posture.Headline(ReportVerdict(report, errors, warnings), ReportVerdictDetail(report, checks));
            if (report.Score.HasValue) posture.Score(report.Score.Value, "of 100").Grade(report.Grade);
            foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
                int[] scores = report.Domains.SelectMany(d => d.Areas).Where(a => a.Area == area && a.Score.HasValue).Select(static a => a.Score!.Value).ToArray();
                if (scores.Length > 0) posture.Meter(AreaLabel(area), (int)Math.Round(scores.Average()));
            }
            // An area without a meter must say why, or it reads as if it was never checked.
            posture.ScoreNote(ScoreNote(report));
            posture.Findings(checks.Count(NeedsAttention), $"checks need attention across {Plural(report.Domains.Count, "domain")}");
            posture.Severity(Severity.High, errors, "Errors");
            posture.Severity(Severity.Elevated, warnings, "Warnings");
            posture.Severity(Severity.Good, passed, "Passed");
            posture.Severity(Severity.Informational, info, "Informational");
            // Neutral, not amber: an evidence gap is not a warning about the domain.
            if (incomplete > 0) posture.Severity(Severity.Skipped, incomplete, "Incomplete evidence");
            posture.Tile(report.Domains.Count.ToString(CultureInfo.InvariantCulture), report.Domains.Count == 1 ? "domain" : "domains");
            posture.Tile(checks.Count.ToString(CultureInfo.InvariantCulture), "checks run");
        });

        var attention = DoFirstGroups(report).ToList();

        section.ReportPanel(panel => {
            panel.Title("Do these first").Subtitle("Shared findings across domains, ordered by severity and how many domains are affected.").Settings(s => s.Flush());
            if (attention.Count == 0) {
                panel.AssessmentStats(stats => stats.Stat("0", "Nothing needs attention", Severity.Good));
                return;
            }
            panel.AssessmentFindings(list => {
                list.Settings(s => s.InitialCount(Math.Max(1, options.FixFirstCount)));
                for (int index = 0; index < attention.Count; index++) {
                    var action = attention[index];
                    var check = action.Check;
                    int count = action.Members.Count;
                    list.Finding(check.Title, OutcomeSeverity(check.Outcome), finding => {
                        finding.Message(DoFirstMessage(check))
                            .SeverityLabel(OutcomeLabel(check.Outcome))
                            .Scope(action.AffectedDomains)
                            .Link(count == 1 ? "Open check" : "Show " + (count == report.Domains.Count ? "all " : string.Empty) + Plural(count, "domain"),
                                count == 1 ? ids.Check(action.Domain, check) : DataExplorer.ShortcutTargetId(ChecksExplorer, "priority-" + index.ToString(CultureInfo.InvariantCulture)));
                        // Part of the source line in the body font; the impact slot is monospace and meant for figures.
                        finding.Source(DoFirstSource(check));
                    });
                }
            });
        });

        RenderAreas(section, report, ids);
        RenderControls(section, report, ids);
        if (report.Domains.Count > 1) RenderRiskByDomain(section, report, ids);
        if (report.Domains.Count > 1) RenderCoverage(section, report, ids);
    }

    private static void RenderCoverage(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var rows = report.Domains
            .SelectMany(static d => d.Checks)
            .GroupBy(static c => c.Key)
            .Select(static g => g.First())
            .OrderBy(static c => AreaIndex(c.Area))
            .ToList();
        section.ReportPanel(panel => panel
            .Title("Coverage")
            .Subtitle("Every check across every domain with its key number. Open a cell for the result; previous and next move along the row.")
            .Settings(s => s.Flush())
            .AssessmentCoverageMatrix(matrix => {
                foreach (DomainAssessment domain in report.Domains) {
                    matrix.Column(ids.Domain(domain), domain.Domain, domain.Score.HasValue ? $"{domain.Grade} · {domain.Score}" : null);
                }
                foreach (CheckAssessment row in rows) {
                    // Cells show the check's key number, so the row names it.
                    string? metricLabel = report.Domains.SelectMany(d => d.Checks.Where(c => c.Key == row.Key)).Select(Headline).FirstOrDefault(static m => m != null)?.Label;
                    matrix.Row(row.Title, metricLabel == null ? AreaLabel(row.Area) : AreaLabel(row.Area) + " · " + metricLabel, cells => {
                        foreach (DomainAssessment domain in report.Domains) {
                            CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == row.Key);
                            if (check == null) continue;
                            int failed = check.ErrorCount + check.WarningCount;
                            CheckMetric? headline = Headline(check);
                            string label = headline?.Value is { Length: > 0 and <= 18 } value ? value : OutcomeLabel(check.Outcome);
                            string title = $"{check.Title} · {domain.Domain} · {OutcomeLabel(check.Outcome)}"
                                + (headline != null ? $" · {headline.Label}: {headline.Value}" : string.Empty)
                                + (failed > 0 ? $" · {Plural(failed, "finding")}" : string.Empty);
                            cells.Cell(ids.Domain(domain), OutcomeSeverity(check.Outcome), check.Outcome == CheckOutcome.Pass ? 1 : 0, failed,
                                label, ids.Check(domain, check), title);
                        }
                    });
                }
            }));
    }

    private static void RenderAbout(AssessmentReportSection section, DomainAssessmentReport report) {
        section.ReportPanel(panel => panel
            .Title("How this report is scored")
            .AssessmentFacts(facts => {
                foreach (var fact in ScoringFacts) facts.Fact(fact.Key, fact.Value);
                if (report.Domains.Any(static d => d.RiskProfile != null)) {
                    facts.Fact("Risk profile", RiskScaleNote + " Rules " + report.Domains.First(static d => d.RiskProfile != null).RiskProfile!.RuleVersion + ".", true);
                }
                facts.Fact("Generated", FormatTime(report.GeneratedAtUtc));
            }));
        if (report.UnassignedInputs.Count > 0) {
            section.ReportPanel(panel => panel
                .Title("Inputs without a domain")
                .Subtitle("Results that did not name a domain and are not shown elsewhere.")
                .Settings(s => s.Muted())
                .AssessmentFacts(facts => {
                    foreach (var group in report.UnassignedInputs.GroupBy(static n => n, StringComparer.Ordinal)) {
                        facts.Fact(group.Key, group.Count().ToString(CultureInfo.InvariantCulture));
                    }
                }));
        }
    }


}
