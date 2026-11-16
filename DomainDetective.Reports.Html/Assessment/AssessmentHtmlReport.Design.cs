using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using static DomainDetective.Reports.AssessmentReportWording;
using HtmlForgeX;

namespace DomainDetective.Reports.Html;

/// <summary>
/// The summary's area rows and control tiles. Both are plain markup styled with the shell's own theme tokens, so they
/// follow light and dark mode and stay compact: one row per area, one even tile per control.
/// </summary>
public static partial class AssessmentHtmlReport {
    // Tones map to the shell's status colours: good green, warn amber, bad red, neutral grey for missing evidence.
    private const string DesignCss = """
.dd-tone-good{--dd-tone:var(--hfx-color-status-good-solid)}
.dd-tone-warn{--dd-tone:var(--hfx-color-status-warn-solid)}
.dd-tone-bad{--dd-tone:var(--hfx-color-status-bad-solid)}
.dd-tone-neutral{--dd-tone:var(--hfx-color-status-neutral-solid)}
.dd-tone-info{--dd-tone:var(--hfx-color-status-info-solid)}
.dd-areas{display:grid}
.dd-area{display:grid;grid-template-columns:minmax(132px,1fr) minmax(112px,.8fr) minmax(0,2.6fr) auto;gap:6px 22px;align-items:center;padding:12px 20px;border-top:1px solid var(--hfx-color-border);color:inherit;text-decoration:none}
.dd-area:first-child{border-top:0}
a.dd-area:hover{background:var(--hfx-color-hover)}
.dd-area-name{display:flex;flex-direction:column;gap:2px;min-width:0}
.dd-area-name b{font-weight:600;font-size:14.5px}
.dd-status{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--hfx-color-text-secondary)}
.dd-status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--dd-tone);flex:none}
.dd-area-score{display:flex;flex-direction:column;gap:1px}
.dd-area-score b{font-size:20px;line-height:1.1;font-weight:600;font-variant-numeric:tabular-nums}
.dd-area-score span{font-size:12px;color:var(--hfx-color-text-muted)}
.dd-area-detail{display:flex;flex-direction:column;gap:5px;min-width:0}
.dd-bar{display:flex;height:6px;border-radius:3px;overflow:hidden;background:var(--hfx-color-surface-sunken)}
.dd-bar i{display:block;height:100%}
.dd-bar .dd-good{background:var(--hfx-color-status-good-solid)}
.dd-bar .dd-warn{background:var(--hfx-color-status-warn-solid)}
.dd-bar .dd-bad{background:var(--hfx-color-status-bad-solid)}
.dd-bar .dd-neutral{background:var(--hfx-color-status-neutral-solid);opacity:.55}
.dd-line{font-size:12.5px;color:var(--hfx-color-text-secondary);overflow-wrap:anywhere}
.dd-line.dd-muted{color:var(--hfx-color-text-muted)}
.dd-open{font-size:12.5px;color:var(--hfx-color-accent-text);white-space:nowrap}
.dd-controls{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,190px),1fr));gap:1px;background:var(--hfx-color-border);border-top:1px solid var(--hfx-color-border)}
.dd-control{display:flex;flex-direction:column;gap:3px;padding:12px 16px 13px;background:var(--hfx-color-surface);color:inherit;text-decoration:none;box-shadow:inset 3px 0 0 var(--dd-tone);min-width:0}
a.dd-control:hover{background:var(--hfx-color-hover)}
.dd-control-name{font-size:12px;color:var(--hfx-color-text-muted)}
.dd-control-value{font-size:16px;font-weight:600;color:var(--dd-tone);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dd-control-reason{font-size:12.5px;color:var(--hfx-color-text-secondary);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.dd-risk{display:grid;gap:18px;padding:4px 0 2px}
.dd-risk-head{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr) minmax(0,1fr);gap:18px 28px}
.dd-risk-word{font-size:26px;line-height:1.15;font-weight:650;color:var(--dd-tone);letter-spacing:-.01em}
.dd-risk-reason{margin:4px 0 0;font-size:13.5px;color:var(--hfx-color-text-secondary);max-width:62ch}
.dd-kpi{display:flex;flex-direction:column;gap:4px;padding-left:18px;border-left:1px solid var(--hfx-color-border)}
.dd-kpi-label{font-size:12.5px;color:var(--hfx-color-text-muted)}
.dd-kpi-value{font-size:20px;font-weight:600;font-variant-numeric:tabular-nums}
.dd-kpi .dd-bar{margin-top:2px}
.dd-kpi-note{font-size:12px;color:var(--hfx-color-text-muted)}
.dd-signals{list-style:none;margin:0;padding:0;display:grid;border-top:1px solid var(--hfx-color-border)}
.dd-signals li{display:grid;grid-template-columns:44px minmax(0,1fr) auto;gap:12px;padding:7px 0;border-bottom:1px solid var(--hfx-color-border);font-size:13.5px;align-items:baseline}
.dd-pts{font-weight:600;font-variant-numeric:tabular-nums;text-align:right;color:var(--dd-tone)}
.dd-src{font-size:12px;color:var(--hfx-color-text-muted);white-space:nowrap}
.dd-note{margin:0;font-size:13.5px;color:var(--hfx-color-text-secondary)}
.dd-note b{font-weight:600;color:var(--hfx-color-text)}
.dd-watch{padding:9px 12px;border-radius:var(--hfx-radius-control,6px);background:var(--hfx-color-surface-sunken);box-shadow:inset 3px 0 0 var(--hfx-color-status-warn-solid)}
.dd-cover{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:12.5px;color:var(--hfx-color-text-secondary)}
.dd-cover span{display:inline-flex;align-items:center;gap:6px;cursor:help}
.dd-cover span::before{content:"";width:8px;height:8px;border-radius:50%;border:1.5px solid var(--dd-tone);background:var(--dd-fill,transparent)}
.dd-cover .dd-seen{--dd-tone:var(--hfx-color-status-good-solid);--dd-fill:var(--hfx-color-status-good-solid)}
.dd-cover .dd-part{--dd-tone:var(--hfx-color-status-good-solid);--dd-fill:linear-gradient(90deg,var(--hfx-color-status-good-solid) 50%,transparent 50%)}
.dd-cover .dd-none{--dd-tone:var(--hfx-color-status-neutral-solid)}
.dd-facts{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,340px),1fr));gap:18px 36px}
.dd-facts h4,.dd-gaps h4{margin:0 0 6px;font-size:13px;font-weight:600;color:var(--hfx-color-text)}
.dd-facts dl{margin:0;display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;font-size:13px}
.dd-facts dt{color:var(--hfx-color-text-muted);white-space:nowrap}
.dd-facts dd{margin:0;overflow-wrap:break-word;color:var(--hfx-color-text)}
.dd-risk a,.dd-note a{text-decoration:underline;text-underline-offset:3px;color:var(--hfx-color-accent-text)}
.dd-gaps ul{margin:0;padding-left:18px;font-size:13px;color:var(--hfx-color-text-secondary);display:grid;gap:3px}
@media (max-width:760px){
.dd-area{grid-template-columns:minmax(0,1fr) auto;padding:12px 14px}
.dd-area-detail{grid-column:1/-1}
.dd-area .dd-open{display:none}
.dd-risk-head{grid-template-columns:1fr 1fr}
.dd-risk-head>:first-child{grid-column:1/-1}
.dd-kpi:nth-child(2){padding-left:0;border-left:0}
.dd-signals li{grid-template-columns:40px minmax(0,1fr)}
.dd-signals .dd-src{grid-column:2}
}
""";

    private static string Tone(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => "dd-tone-bad",
        CheckOutcome.Warning => "dd-tone-warn",
        CheckOutcome.Pass => "dd-tone-good",
        CheckOutcome.Incomplete => "dd-tone-neutral",
        _ => "dd-tone-info"
    };

    private static string AreaTone(IReadOnlyCollection<CheckAssessment> checks) => AreaStatus(checks) switch {
        "Errors" => "dd-tone-bad",
        "Needs attention" => "dd-tone-warn",
        "Partly checked" => "dd-tone-neutral",
        "Passing" => "dd-tone-good",
        _ => "dd-tone-info"
    };

    private static HtmlTag Span(string text, string? css = null) => new HtmlTag("span").Class(css).Value(text);

    /// <summary>One compact row per area: status, score with how much of it could be judged, counts with a bar, and what to look at.</summary>
    private static void RenderAreas(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var areas = DomainAssessmentCatalog.AreaOrder
            .Select(area => (Area: area, Checks: report.Domains.SelectMany(d => d.Checks.Where(c => c.Area == area)).ToList()))
            .Where(static a => a.Checks.Count > 0)
            .ToList();
        if (areas.Count == 0) return;
        DomainAssessment? single = report.Domains.Count == 1 ? report.Domains[0] : null;
        section.ReportPanel(panel => {
            panel.Title("Area by area")
                .Subtitle(report.Domains.Count == 1 ? "Each area's score counts the checks that could be judged." : "Scores are the average across domains.")
                .Settings(s => s.Flush());
            var list = new HtmlTag("div").Class("dd-areas");
            foreach (var (area, checks) in areas) {
                (int? score, double? coverage) = DomainAssessmentCatalog.AreaScore(report, area);
                bool scored = checks.Any(static c => c.Scored);
                var row = new HtmlTag(single != null ? "a" : "div").Class("dd-area " + AreaTone(checks));
                if (single != null) row.Attribute("href", "#" + ids.Domain(single));

                row.Value(new HtmlTag("div").Class("dd-area-name")
                    .Value(new HtmlTag("b").Value(AreaLabel(area)))
                    .Value(Span(AreaStatus(checks), "dd-status")));

                var scoreCell = new HtmlTag("div").Class("dd-area-score");
                DomainDetective.Profiles.DomainRiskProfile? risk = area == AnalysisArea.Reputation ? single?.RiskProfile : null;
                if (risk != null) {
                    scoreCell.Value(new HtmlTag("b").Class(RiskToneClass(risk)).Style("color", "var(--dd-tone)").Value(RiskWord(risk)))
                        .Value(Span(ConfidencePercent(risk)));
                } else if (score.HasValue) {
                    scoreCell.Value(new HtmlTag("b").Value(score.Value.ToString(CultureInfo.InvariantCulture)))
                        .Value(Span(coverage is < 0.995 ? CoveragePercent(coverage) + " of checks judged" : "of 100"));
                } else {
                    scoreCell.Value(new HtmlTag("b").Class("dd-muted").Style("color", "var(--hfx-color-text-muted)").Value(scored ? "Not judged" : "–"))
                        .Value(Span(scored ? "evidence incomplete" : "informational only"));
                }
                row.Value(scoreCell);

                var detail = new HtmlTag("div").Class("dd-area-detail");
                if (scored) detail.Value(AreaBar(checks));
                detail.Value(Span(AreaCounts(checks), "dd-line"));
                if (AreaMissing(checks) is { } missing) detail.Value(Span(missing, "dd-line dd-muted"));
                row.Value(detail);
                row.Value(Span(single != null ? "Open checks" : string.Empty, "dd-open"));
                list.Value(row);
            }
            panel.Add(list);
        });
    }

    private static HtmlTag AreaBar(IReadOnlyCollection<CheckAssessment> checks) {
        int pass = checks.Count(static c => c.Scored && c.Outcome == CheckOutcome.Pass);
        int warn = checks.Count(static c => c.Outcome == CheckOutcome.Warning);
        int bad = checks.Count(static c => c.Outcome == CheckOutcome.Error);
        int open = checks.Count(static c => c.Scored && !c.EvidenceComplete && c.Outcome is not (CheckOutcome.Error or CheckOutcome.Warning));
        int total = Math.Max(1, pass + warn + bad + open);
        var bar = new HtmlTag("div").Class("dd-bar").Attribute("role", "img")
            .Attribute("aria-label", AreaCounts(checks));
        void Part(int count, string css) {
            if (count > 0) bar.Value(new HtmlTag("i").Class(css).Style("width", (100.0 * count / total).ToString("0.##", CultureInfo.InvariantCulture) + "%"));
        }
        Part(pass, "dd-good");
        Part(warn, "dd-warn");
        Part(bad, "dd-bad");
        Part(open, "dd-neutral");
        return bar;
    }

    /// <summary>One even tile per control: a value a reader understands, coloured by outcome, and a one-line reason.</summary>
    // An unscored state every domain shares (no CAA policy) is shown as itself, not as "0 of N pass".
    private static string? SharedNeutralValue(IReadOnlyList<CheckAssessment> results) {
        if (results.Count == 0 || results.Any(static c => c.Scored || c.Outcome != CheckOutcome.Info)) return null;
        string value = ControlValue(results[0]);
        return results.All(c => ControlValue(c) == value) ? value : null;
    }

    private static void RenderControls(AssessmentReportSection section, DomainAssessmentReport report, CheckIds ids) {
        var present = ControlChecks(report).ToList();
        if (present.Count == 0) return;
        section.ReportPanel(panel => {
            panel.Title("Controls")
                .Anchor("dd-summary-controls")
                .Subtitle(report.Domains.Count == 1 ? "Each control in a word, and why. Open one for the detail." : "Domains where each control passes.")
                .Settings(s => s.Flush());
            var grid = new HtmlTag("div").Class("dd-controls");
            foreach (CheckAssessment first in present) {
                string key = first.Key;
                if (report.Domains.Count == 1) {
                    DomainAssessment domain = report.Domains[0];
                    CheckAssessment check = domain.Checks.First(c => c.Key == key);
                    grid.Value(new HtmlTag("a").Class("dd-control " + Tone(check.Outcome)).Attribute("href", "#" + ids.Check(domain, check))
                        .Attribute("title", check.LongTitle ?? check.Title)
                        .Value(Span(check.Title, "dd-control-name"))
                        .Value(Span(ControlValue(check), "dd-control-value"))
                        .Value(Span(ControlReason(check), "dd-control-reason")));
                } else {
                    var results = report.Domains.Select(d => d.Checks.FirstOrDefault(c => c.Key == key)).Where(static c => c != null).Select(static c => c!).ToList();
                    int passing = results.Count(static c => c.Scored && c.Outcome == CheckOutcome.Pass);
                    CheckOutcome worst = results.Max(static c => c.Outcome);
                    string tone = results.Any(static c => c.Outcome == CheckOutcome.Error) ? "dd-tone-bad"
                        : results.Any(static c => c.Outcome == CheckOutcome.Warning) ? "dd-tone-warn"
                        : results.Any(static c => !c.EvidenceComplete) ? "dd-tone-neutral"
                        : passing == results.Count ? "dd-tone-good" : Tone(worst);
                    grid.Value(new HtmlTag("div").Class("dd-control " + tone)
                        .Value(Span(first.Title, "dd-control-name"))
                        .Value(Span(SharedNeutralValue(results) ?? passing.ToString(CultureInfo.InvariantCulture) + " of " + Plural(results.Count, "domain") + " pass", "dd-control-value"))
                        .Value(Span(results.Where(static c => c.Outcome != CheckOutcome.Pass).Select(ControlReason).FirstOrDefault(static r => r.Length > 0) ?? string.Empty, "dd-control-reason")));
                }
            }
            panel.Add(grid);
        });
    }
}
