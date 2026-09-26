using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Reports;
using HtmlForgeX;
using Severity = HtmlForgeX.AssessmentSeverity;

namespace DomainDetective.Reports.Html;

public static partial class AssessmentHtmlReport {
    private static void RenderGuidance(AssessmentCheck row, CheckAssessment check) {
        var narrative = check.Narrative;
        bool needsFix = check.Outcome is CheckOutcome.Error or CheckOutcome.Warning;
        string? why = narrative?.WhyItMatters;
        List<string> remediations = narrative?.Remediations.Where(static r => !string.IsNullOrWhiteSpace(r)).ToList() ?? new List<string>();
        if (remediations.Count == 0 && needsFix && !string.IsNullOrWhiteSpace(check.Remediation)) remediations.Add(check.Remediation!);
        List<CheckGuidance> recommendations = needsFix ? check.Recommendations : new List<CheckGuidance>();
        // Recommendations are specific to what this run found; narrative remediations are generic, so they are only
        // the fallback.
        if (recommendations.Count > 0) remediations.Clear();
        if (string.IsNullOrWhiteSpace(why) && remediations.Count == 0 && recommendations.Count == 0 && check.References.Count == 0) return;

        row.AssessmentPanel(panel => {
            panel.Title(needsFix ? "How to fix" : "Guidance").TitleIcon(TablerIconType.Bulb).Settings(s => s.Muted());
            if (!string.IsNullOrWhiteSpace(why)) panel.Text(why!);
            if (needsFix && remediations.Count > 0) panel.Add(BulletList(remediations));
            if (recommendations.Count > 0) panel.Add(RecommendationList(recommendations));
            if (check.References.Count > 0) panel.Add(LinkList(check.References));
        });
    }

    private static void RenderEvidence(AssessmentCheck row, CheckAssessment check) {
        if (check.Facts.Count == 0 && check.Evidence.Count == 0 && check.Highlights.Count == 0) return;
        row.AssessmentPanel(panel => {
            panel.Title("Evidence").TitleIcon(TablerIconType.FileSearch).Settings(s => s.Flush());
            if (check.Highlights.Count > 0) panel.Add(BulletList(check.Highlights));
            if (check.Facts.Count > 0) {
                panel.AssessmentFacts(facts => {
                    foreach (CheckFact fact in check.Facts) facts.Fact(fact.Label, fact.Value, fact.Value.Length > 40);
                });
            }
            foreach (CheckEvidence evidence in check.Evidence) {
                panel.Add(new HtmlTag("h4").Class("dd-evidence-title").Value(evidence.Title));
                switch (evidence.Kind) {
                    case CheckEvidenceKind.Code:
                        panel.Add(new HtmlTag("pre").Class("dd-evidence-code").Value(new HtmlTag("code").Value(evidence.Text ?? string.Empty)));
                        break;
                    case CheckEvidenceKind.List:
                        panel.Add(BulletList(evidence.Items));
                        break;
                    case CheckEvidenceKind.Table:
                        panel.Add(EvidenceTable(evidence));
                        break;
                }
                if (evidence.Omitted > 0) {
                    panel.Add(new HtmlTag("p").Class("text-secondary small").Value($"{evidence.Omitted.ToString("N0", CultureInfo.InvariantCulture)} more not shown."));
                }
            }
        });
    }

    private static HtmlTag EvidenceTable(CheckEvidence evidence) {
        var head = new HtmlTag("tr");
        foreach (string column in evidence.Columns) head.Value(new HtmlTag("th").Value(column));
        var body = new HtmlTag("tbody");
        foreach (List<string> cells in evidence.Rows) {
            var tr = new HtmlTag("tr");
            foreach (string cell in cells) tr.Value(new HtmlTag("td").Value(cell));
            body.Value(tr);
        }
        return new HtmlTag("div").Class("table-responsive dd-evidence-table").Value(
            new HtmlTag("table").Class("table table-sm table-vcenter").Value(new HtmlTag("thead").Value(head)).Value(body));
    }

    private static HtmlTag RecommendationList(IEnumerable<CheckGuidance> recommendations) {
        var list = new HtmlTag("ul").Class("dd-recommendations");
        foreach (CheckGuidance advice in recommendations) {
            var item = new HtmlTag("li").Value(new HtmlTag("strong").Value(advice.Title));
            string detail = string.Join(" ", new[] { advice.How, advice.Why }.Where(static s => !string.IsNullOrWhiteSpace(s)));
            if (detail.Length > 0) item.Value(new HtmlTag("div").Class("text-secondary").Value(detail));
            if (!string.IsNullOrWhiteSpace(advice.Verify)) item.Value(new HtmlTag("div").Class("text-secondary small").Value("Verify: " + advice.Verify));
            list.Value(item);
        }
        return list;
    }

    private static HtmlTag BulletList(IEnumerable<string> items) {
        var list = new HtmlTag("ul").Class("dd-evidence-list");
        foreach (string item in items) list.Value(new HtmlTag("li").Value(item));
        return list;
    }

    private static HtmlTag LinkList(IEnumerable<string> links) {
        var list = new HtmlTag("ul").Class("dd-evidence-links");
        foreach (string link in links) {
            bool web = Uri.TryCreate(link, UriKind.Absolute, out Uri? uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
            list.Value(new HtmlTag("li").Value(web
                ? new HtmlTag("a").Attribute("href", uri!.AbsoluteUri).Attribute("target", "_blank").Attribute("rel", "noopener noreferrer").Value(link)
                : new HtmlTag("span").Value(link)));
        }
        return list;
    }

    private static Severity OutcomeSeverity(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => Severity.High,
        CheckOutcome.Warning => Severity.Elevated,
        CheckOutcome.Pass => Severity.Good,
        _ => Severity.Informational
    };

    private static string OutcomeLabel(CheckOutcome outcome) => outcome switch {
        CheckOutcome.Error => "Error",
        CheckOutcome.Warning => "Warning",
        CheckOutcome.Pass => "Pass",
        _ => "Info"
    };

    private static Severity FindingSeverity(AssessmentSeverity severity) => severity switch {
        AssessmentSeverity.Error => Severity.High,
        AssessmentSeverity.Warning => Severity.Elevated,
        _ => Severity.Informational
    };

    private static Severity GradeSeverity(int? score) => score switch {
        null => Severity.Skipped,
        >= 90 => Severity.Good,
        >= 70 => Severity.Low,
        >= 60 => Severity.Elevated,
        _ => Severity.High
    };

    private static string AreaLabel(AnalysisArea area) => area switch {
        AnalysisArea.DNS => "DNS",
        AnalysisArea.General => "Other",
        _ => area.ToString()
    };

    private static string AreaKey(AnalysisArea area) => "area-" + area.ToString().ToLowerInvariant();

    private static int AreaIndex(AnalysisArea area) {
        for (int i = 0; i < DomainAssessmentCatalog.AreaOrder.Count; i++) {
            if (DomainAssessmentCatalog.AreaOrder[i] == area) return i;
        }
        return int.MaxValue;
    }

    private static string Plural(int count, string noun)
        => $"{count.ToString("N0", CultureInfo.InvariantCulture)} {noun}{(count == 1 ? string.Empty : "s")}";

    private static string FormatTime(DateTimeOffset value) => value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture);
}
