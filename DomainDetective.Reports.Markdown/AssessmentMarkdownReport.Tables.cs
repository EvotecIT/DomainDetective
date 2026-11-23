using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using OfficeIMO.Markdown;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Markdown;

public static partial class AssessmentMarkdownReport {
    private static void WriteAreas(MarkdownDocument document, DomainAssessmentReport report) {
        document.H2("Area by area");
        var rows = new List<string[]>();
        foreach (AnalysisArea area in DomainAssessmentCatalog.AreaOrder) {
            List<CheckAssessment> checks = report.Domains.SelectMany(static d => d.Checks).Where(c => c.Area == area).ToList();
            if (checks.Count == 0) { continue; }
            (int? score, double? coverage) = DomainAssessmentCatalog.AreaScore(report, area);
            int errors = checks.Count(static c => c.Outcome == CheckOutcome.Error);
            int warnings = checks.Count(static c => c.Outcome == CheckOutcome.Warning);
            bool incomplete = checks.Any(static c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete);
            rows.Add(new[] {
                Wording.AreaLabel(area),
                Wording.AreaStatus(checks),
                score.HasValue
                    ? score.Value.ToString(CultureInfo.InvariantCulture) + (coverage is < 0.995 ? " (" + Wording.CoveragePercent(coverage) + " judged)" : string.Empty)
                    : "Not scored",
                checks.Count.ToString(CultureInfo.InvariantCulture),
                checks.Count(static c => c.Scored && c.Outcome == CheckOutcome.Pass).ToString(CultureInfo.InvariantCulture),
                checks.Count(Wording.NeedsAttention).ToString(CultureInfo.InvariantCulture),
                Wording.AreaNote(report, checks)
            });
        }
        AddTable(document, new[] { "Area", "Status", "Score", "Checks", "Passing", "Needs attention", "Notes" }, rows);
    }

    private static void WriteChecks(MarkdownDocument document, IEnumerable<CheckAssessment> checks) {
        AddTable(document, new[] { "Check", "Outcome", "Key number", "Score", "Errors", "Warnings", "Top finding" }, checks.Select(static check => {
            CheckMetric? headline = Wording.Headline(check);
            return new[] {
                check.Title, Wording.OutcomeLabel(check.Outcome), headline == null ? string.Empty : headline.Label + ": " + headline.Value,
                check.Scored && check.EvidenceComplete ? check.Score?.ToString(CultureInfo.InvariantCulture) ?? "Not scored" : "Not scored",
                check.ErrorCount.ToString(CultureInfo.InvariantCulture), check.WarningCount.ToString(CultureInfo.InvariantCulture),
                Wording.TopFinding(check) ?? string.Empty
            };
        }));
    }

    /// <summary>Uses the native table model without the fluent builder's row limit: every captured row is retained.</summary>
    private static void AddTable(MarkdownDocument document, IEnumerable<string> headers, IEnumerable<IEnumerable<string>> rows) {
        var table = new TableBlock();
        table.Headers.AddRange(headers.Select(InlineText));
        foreach (IEnumerable<string> row in rows) { table.Rows.Add(row.Select(InlineText).ToArray()); }
        document.Add(table);
    }

    /// <summary>
    /// Makes a report field one readable line. OfficeIMO owns Markdown/HTML escaping; raw record text is emitted
    /// separately through its fenced-code writer and retains its original whitespace.
    /// </summary>
    private static string InlineText(string? value) {
        if (string.IsNullOrEmpty(value)) { return string.Empty; }
        var text = new StringBuilder(value!.Length);
        for (int index = 0; index < value.Length; index++) {
            char character = value[index];
            if (char.IsWhiteSpace(character)) {
                if (text.Length > 0 && text[text.Length - 1] != ' ') { text.Append(' '); }
            } else {
                text.Append(character);
            }
        }
        return text.ToString().TrimEnd();
    }
}
