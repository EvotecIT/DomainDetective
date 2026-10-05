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
            int attention = report.Domains.Sum(static d => d.ErrorChecks + d.WarningChecks);
            bool anyError = report.Domains.Any(static d => d.ErrorChecks > 0);
            shell.AddSection("Explore", section => {
                section.Key("explore").NavigationIcon(TablerIconType.ListSearch)
                    .NavigationDetail("Every check and finding")
                    .Count(attention, anyError ? Severity.High : attention > 0 ? Severity.Elevated : Severity.Good, "checks need attention");
                RenderExplore(section, report, ids);
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

        section.AssessmentPosture(posture => {
            posture.Headline(ReportVerdict(report, errors, warnings), ReportVerdictDetail(report, checks));
            posture.Score(report.Score ?? 0, "of 100", report.Score.HasValue ? null : "Nothing scored");
            if (report.Score.HasValue) posture.Grade(report.Grade);
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
        });

        // The same order as the verdict's "Fix first": errors before warnings, then what costs the score most.
        var attention = report.Domains
            .SelectMany(static d => d.Checks.Select(c => (Domain: d, Check: c)))
            .Where(static x => x.Check.Outcome is CheckOutcome.Error or CheckOutcome.Warning)
            .OrderByDescending(static x => x.Check.Outcome)
            .ThenByDescending(static x => (100 - x.Check.Score) * Math.Max(1, x.Check.Weight))
            .ToList();

        section.ReportPanel(panel => {
            panel.Title("Do these first").Subtitle("Errors before warnings, then the checks that cost the score most.").Settings(s => s.Flush());
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

        RenderAreas(section, report, ids);
        RenderControls(section, report, ids);
        if (report.Domains.Count > 1) RenderCoverage(section, report, ids);
    }

    /// <summary>
    /// One card per area: its score, how many checks pass, and in one line what needs attention. For one domain a card
    /// opens the domain's checks; for several it averages the domain scores.
    /// </summary>
    private static void RenderAreas(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var areas = DomainAssessmentCatalog.AreaOrder
            .Select(area => (Area: area, Checks: report.Domains.SelectMany(d => d.Checks.Where(c => c.Area == area)).ToList()))
            .Where(static a => a.Checks.Count > 0)
            .ToList();
        if (areas.Count == 0) return;
        section.ReportPanel(panel => panel
            .Title("Area by area")
            .Subtitle(report.Domains.Count == 1 ? "Open an area for its checks." : "Scores are the average across domains.")
            .Settings(s => s.Flush())
            .AssessmentScopes(list => {
                list.Settings(s => s.Layout(AssessmentScopeLayout.Cards));
                foreach (var (area, areaChecks) in areas) {
                    int[] scores = report.Domains.SelectMany(d => d.Areas).Where(a => a.Area == area && a.Score.HasValue).Select(static a => a.Score!.Value).ToArray();
                    int? score = scores.Length == 0 ? null : (int)Math.Round(scores.Average());
                    int errors = areaChecks.Count(static c => c.Outcome == CheckOutcome.Error);
                    int warnings = areaChecks.Count(static c => c.Outcome == CheckOutcome.Warning);
                    int passed = areaChecks.Count(static c => c.Outcome is CheckOutcome.Pass or CheckOutcome.Info);
                    Severity tone = errors > 0 ? Severity.High : warnings > 0 ? Severity.Elevated : score.HasValue ? Severity.Good : Severity.Informational;
                    list.Scope(AreaLabel(area), tone, item => {
                        item.Status(errors > 0 ? "Errors" : warnings > 0 ? "Needs attention" : "Passing");
                        item.Metric("Score", score?.ToString(CultureInfo.InvariantCulture) ?? "-", GradeSeverity(score));
                        item.Metric("Checks", areaChecks.Count.ToString(CultureInfo.InvariantCulture));
                        item.Progress(passed, errors + warnings);
                        item.Note(AreaLine(report, areaChecks));
                        if (report.Domains.Count == 1) item.Link("Open checks", ids.Domain(report.Domains[0]));
                    });
                }
            }));
    }

    /// <summary>What needs attention in an area, in one line.</summary>
    private static string AreaLine(DomainAssessmentReport report, List<CheckAssessment> checks) {
        var titles = FixOrder(checks).Select(static c => c.Title).Distinct(StringComparer.Ordinal).ToList();
        if (titles.Count == 0) return checks.All(static c => !c.Scored) ? "Informational checks only." : $"All {Plural(checks.Count, "check")} pass.";
        string list = titles.Count <= 3 ? string.Join(", ", titles) : string.Join(", ", titles.Take(3)) + $" and {Plural(titles.Count - 3, "more")}";
        return report.Domains.Count == 1 ? "Needs attention: " + list + "." : "Needs attention on some domains: " + list + ".";
    }

    /// <summary>The verdict across the top of the summary: what the run found, in one or two sentences.</summary>
    private static string ReportVerdict(DomainAssessmentReport report, int errors, int warnings) {
        int open = errors + warnings;
        string need = open == 1 ? "needs" : "need";
        string attention = open == 0
            ? "Every check passed."
            : errors == 0
                ? $"{Plural(open, "check")} {need} attention; none has errors."
                : open == 1
                    ? "1 check has errors."
                    : $"{Plural(open, "check")} {need} attention, {errors.ToString(CultureInfo.InvariantCulture)} of them with errors.";
        if (report.Domains.Count == 1) {
            string? strengths = DomainStrengths(report.Domains[0]);
            return strengths == null ? attention : strengths + " " + attention;
        }
        int withErrors = report.Domains.Count(static d => d.ErrorChecks > 0);
        int warningsOnly = report.Domains.Count(static d => d.ErrorChecks == 0 && d.WarningChecks > 0);
        int clean = report.Domains.Count - withErrors - warningsOnly;
        var parts = new List<string>();
        if (withErrors > 0) parts.Add($"{withErrors.ToString(CultureInfo.InvariantCulture)} with errors");
        if (warningsOnly > 0) parts.Add($"{warningsOnly.ToString(CultureInfo.InvariantCulture)} with warnings only");
        if (clean > 0) parts.Add($"{clean.ToString(CultureInfo.InvariantCulture)} passing every check");
        return $"Of {Plural(report.Domains.Count, "domain")}, " + JoinList(parts) + ".";
    }

    private static string ReportVerdictDetail(DomainAssessmentReport report, List<CheckAssessment> checks) {
        int areas = checks.Select(static c => c.Area).Distinct().Count();
        int passed = checks.Count(static c => c.Outcome == CheckOutcome.Pass);
        int info = checks.Count(static c => c.Outcome == CheckOutcome.Info);
        string what = $"{Plural(checks.Count, "check")} in {Plural(areas, "area")}: {passed.ToString(CultureInfo.InvariantCulture)} passed";
        if (info > 0) what += $", {info.ToString(CultureInfo.InvariantCulture)} informational";
        return what + (report.Domains.Count > 1 ? ". The overall grade averages the domain scores." : ".");
    }

    private static string JoinList(List<string> parts) => parts.Count switch {
        0 => string.Empty,
        1 => parts[0],
        _ => string.Join(", ", parts.Take(parts.Count - 1)) + " and " + parts[parts.Count - 1]
    };

    // The controls a reader looks for first, with the number that says most about each.
    private static readonly (string Key, string Headline)[] Controls = {
        ("dmarc", "Policy"), ("spf", "Ends with"), ("dkim", "Selectors found"), ("mx", "Mail servers"),
        ("mtasts", "Mode"), ("tlsrpt", "Report addresses"), ("bimi", "Logo"), ("dnssec", string.Empty), ("caa", string.Empty)
    };

    /// <summary>
    /// One tile per key control. For one domain the tile shows the control's headline number and opens the check; for
    /// several it shows how many domains pass.
    /// </summary>
    private static void RenderControls(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var present = Controls.Where(c => report.Domains.Any(d => d.Checks.Any(check => check.Key == c.Key))).ToList();
        if (present.Count == 0) return;
        section.ReportPanel(panel => panel
            .Title("Controls")
            .Subtitle(report.Domains.Count == 1 ? "The number that matters most for each control. Open one for the detail." : "Domains where each control passes.")
            .Settings(s => s.Flush())
            .AssessmentStats(stats => {
                foreach (var (key, _) in present) {
                    if (report.Domains.Count == 1) {
                        DomainAssessment domain = report.Domains[0];
                        CheckAssessment check = domain.Checks.First(c => c.Key == key);
                        string value = Headline(check)?.Value ?? OutcomeLabel(check.Outcome);
                        stats.Stat(value, check.Title, OutcomeSeverity(check.Outcome), ids.Check(domain, check));
                    } else {
                        var results = report.Domains.Select(d => d.Checks.FirstOrDefault(c => c.Key == key)).Where(static c => c != null).ToList();
                        int passing = results.Count(static c => c!.Outcome is CheckOutcome.Pass or CheckOutcome.Info);
                        string title = results[0]!.Title;
                        Severity tone = passing == results.Count ? Severity.Good : results.Any(static c => c!.Outcome == CheckOutcome.Error) ? Severity.High : Severity.Elevated;
                        stats.Stat($"{passing.ToString(CultureInfo.InvariantCulture)} / {results.Count.ToString(CultureInfo.InvariantCulture)}", title, tone);
                    }
                }
            }));
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
                            cells.Cell(ids.Domain(domain), OutcomeSeverity(check.Outcome), failed == 0 ? 1 : 0, failed,
                                label, ids.Check(domain, check), title);
                        }
                    });
                }
            }));
    }

    private static void RenderAbout(AssessmentReportSection section, DomainAssessmentReport report) {
        section.ReportPanel(panel => panel
            .Title("How this report is scored")
            .AssessmentFacts(facts => facts
                .Fact("Check score", "100 when a check passes; 15 points off per warning (not below 50); with errors, 40 for the first, 10 less for each further error and 5 less per warning (not below 0).")
                .Fact("Domain score", "Weighted average of scored checks. DMARC counts three times, SPF, DKIM, MX and DNSSEC twice.")
                .Fact("Informational checks", "Inventory and discovery checks (subdomains, DNS inventory, CT timeline, Microsoft 365, ...) are shown but not scored.")
                .Fact("Grade", "A from 90, B from 80, C from 70, D from 60, otherwise F.")
                .Fact("Generated", FormatTime(report.GeneratedAtUtc))));
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

    private static string ScoreNote(int? score, int errors, int warnings) {
        if (!score.HasValue) return "No scored checks ran.";
        if (errors == 0 && warnings == 0) return "Every scored check passed.";
        return $"{Plural(errors, "check")} with errors and {Plural(warnings, "check")} with warnings.";
    }
}
