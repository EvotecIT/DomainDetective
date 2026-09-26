using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
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

    /// <summary>Number of items in the summary's "Fix first" list before it expands. Defaults to 8.</summary>
    public int FixFirstCount { get; set; } = 8;
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

        var ids = new CheckIds(report);
        document.Body.AssessmentReport(shell => {
            shell.Brand(options.Brand, null)
                .Title(report.Title)
                .Subtitle(options.Subtitle ?? DefaultSubtitle(report));
            shell.Settings(settings => settings.NavigationLabel("Report sections"));

            shell.AddSection("Summary", section => {
                section.Key("summary").NavigationIcon(TablerIconType.LayoutDashboard).Active();
                RenderSummary(section, report, ids, options);
            });

            if (report.Domains.Count == 1) {
                DomainAssessment domain = report.Domains[0];
                shell.AddSection(domain.Domain, section => RenderDomain(section, domain, ids, options));
            } else if (report.Domains.Count > 1) {
                shell.AddNavigationGroup("Domains", group => {
                    group.Key("domains").NavigationIcon(TablerIconType.World);
                    group.Settings(s => s.InlineUpTo(1).SearchAbove(8).Labels("Filter domains", "No matching domains", "Checks"));
                    foreach (DomainAssessment domain in report.Domains) {
                        group.AddSection(domain.Domain, section => RenderDomain(section, domain, ids, options));
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

        section.AssessmentPosture(posture => {
            posture.Score(report.Score ?? 0, "Overall / 100", report.Score.HasValue ? "Grade " + report.Grade : "Nothing scored");
            posture.ScoreNote(ScoreNote(report.Score, errors, warnings));
            foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
                int[] scores = report.Domains.SelectMany(d => d.Areas).Where(a => a.Area == area && a.Score.HasValue).Select(static a => a.Score!.Value).ToArray();
                if (scores.Length > 0) posture.Meter(AreaLabel(area), (int)Math.Round(scores.Average()));
            }
            posture.Findings(errors + warnings, $"checks need attention across {Plural(report.Domains.Count, "domain")}");
            posture.Severity(Severity.High, errors, "Errors");
            posture.Severity(Severity.Elevated, warnings, "Warnings");
            posture.Severity(Severity.Good, passed, "Passed");
            posture.Severity(Severity.Informational, info, "Informational");
            posture.Tile(report.Domains.Count.ToString(CultureInfo.InvariantCulture), report.Domains.Count == 1 ? "domain" : "domains");
            posture.Tile(checks.Count.ToString(CultureInfo.InvariantCulture), "checks run");
            posture.Tile(report.Grade, "overall grade", GradeSeverity(report.Score));
        });

        var attention = report.Domains
            .SelectMany(static d => d.Checks.Select(c => (Domain: d, Check: c)))
            .Where(static x => x.Check.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            .OrderByDescending(static x => x.Check.Outcome)
            .ThenByDescending(static x => x.Check.Weight)
            .ThenByDescending(static x => x.Check.ErrorCount + x.Check.WarningCount)
            .ToList();

        section.AssessmentPanel(panel => {
            panel.Title("Fix first").Subtitle("Checks with errors first, then warnings; mail authentication weighs most.").Settings(s => s.Flush());
            if (attention.Count == 0) {
                panel.AssessmentStats(stats => stats.Stat("0", "Nothing needs attention", Severity.Good));
                return;
            }
            panel.AssessmentFindings(list => {
                list.Settings(s => s.InitialCount(Math.Max(1, options.FixFirstCount)));
                foreach (var (domain, check) in attention) {
                    CheckFinding? top = check.Findings.FirstOrDefault(f => f.Severity != AssessmentSeverity.Info);
                    list.Finding(check.Title, OutcomeSeverity(check.Outcome), finding => {
                        finding.Message(top?.Message ?? check.Summary ?? check.Description ?? string.Empty)
                            .SeverityLabel(OutcomeLabel(check.Outcome))
                            .Scope(domain.Domain, null, ids.Domain(domain))
                            .Source(AreaLabel(check.Area))
                            .Link("Open check", ids.Check(domain, check));
                        int more = check.ErrorCount + check.WarningCount - 1;
                        if (more > 0) finding.Impact($"+{Plural(more, "more finding")}");
                    });
                }
            });
        });

        if (report.Domains.Count > 1) RenderCoverage(section, report, ids);
    }

    private static void RenderCoverage(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var rows = report.Domains
            .SelectMany(static d => d.Checks)
            .GroupBy(static c => c.Key)
            .Select(static g => g.First())
            .OrderBy(static c => AreaIndex(c.Area))
            .ToList();
        section.AssessmentPanel(panel => panel
            .Title("Coverage")
            .Subtitle("Every check across every domain. Open a cell for the result.")
            .Settings(s => s.Flush())
            .AssessmentCoverageMatrix(matrix => {
                foreach (DomainAssessment domain in report.Domains) {
                    matrix.Column(ids.Domain(domain), domain.Domain, domain.Score.HasValue ? $"{domain.Grade} · {domain.Score}" : null);
                }
                foreach (CheckAssessment row in rows) {
                    matrix.Row(row.Title, AreaLabel(row.Area), cells => {
                        foreach (DomainAssessment domain in report.Domains) {
                            CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == row.Key);
                            if (check == null) continue;
                            int failed = check.ErrorCount + check.WarningCount;
                            cells.Cell(ids.Domain(domain), OutcomeSeverity(check.Outcome), failed == 0 ? 1 : 0, failed,
                                OutcomeLabel(check.Outcome), ids.Check(domain, check), $"{check.Title} · {domain.Domain}");
                        }
                    });
                }
            }));
    }

    private static void RenderAbout(AssessmentReportSection section, DomainAssessmentReport report) {
        section.AssessmentPanel(panel => panel
            .Title("How this report is scored")
            .Settings(s => s.Flush())
            .AssessmentFacts(facts => facts
                .Fact("Check score", "100 when a check passes; 15 points off per warning (not below 50); with errors, 40 for the first, 10 less for each further error and 5 less per warning (not below 0).")
                .Fact("Domain score", "Weighted average of scored checks. DMARC counts three times, SPF, DKIM, MX and DNSSEC twice.")
                .Fact("Informational checks", "Inventory and discovery checks (subdomains, DNS inventory, CT timeline, Microsoft 365, ...) are shown but not scored.")
                .Fact("Grade", "A from 90, B from 80, C from 70, D from 60, otherwise F.")
                .Fact("Generated", FormatTime(report.GeneratedAtUtc))));
        if (report.UnassignedInputs.Count > 0) {
            section.AssessmentPanel(panel => panel
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

    private static string ScoreNote(int? score, int errors, int warnings) {
        if (!score.HasValue) return "No scored checks ran.";
        if (errors == 0 && warnings == 0) return "Every scored check passed.";
        return $"{Plural(errors, "check")} with errors and {Plural(warnings, "check")} with warnings.";
    }
}
