using System;
using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    private static void WriteCover(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        List<CheckAssessment> checks = report.Domains.SelectMany(d => d.Checks).ToList();
        style.AddCover(document, "Domain assessment", Identifier(Scope(report)),
            "Generated " + Wording.FormatTime(report.GeneratedAtUtc) + " · " + Wording.Plural(checks.Count, "check")
            + " in " + Wording.Plural(checks.Select(c => c.Area).Distinct().Count(), "area"));
        WordParagraph rule = document.Paragraphs.Last();
        rule.Borders.BottomStyle = WordBorderStyle.Single;
        rule.Borders.BottomColorHex = style.Accent;
        rule.Borders.BottomSize = 24;
        Body(document, style, Wording.ReportVerdict(report), true);
        Body(document, style, Wording.ReportVerdictDetail(report));
        int attention = checks.Count(Wording.NeedsAttention);
        int errors = checks.Count(c => c.Outcome == CheckOutcome.Error);
        int incomplete = checks.Count(c => !c.EvidenceComplete);
        Cards(document, style, new[] {
            (Label: "Grade / score", Value: report.Score.HasValue ? report.Grade + " · " + Score(report.Score) : "Not scored", Tone: ScoreTone(report.Score)),
            (Label: "Checks needing attention", Value: Number(attention), Tone: errors > 0 ? High : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? Elevated : Neutral),
            (Label: "Errors", Value: Number(errors), Tone: errors > 0 ? High : Neutral),
            (Label: "Incomplete evidence", Value: Number(incomplete), Tone: Neutral)
        });
    }

    private static void Cards(WordDocument document, WordPaperStyle style, IEnumerable<(string Label, string Value, string Tone)> values) {
        var cards = values.ToArray();
        if (cards.Length == 0) { return; }
        WordTable table = document.AddTable(1, cards.Length, WordTableStyle.TableNormal);
        style.ApplyTable(table, hasHeader: false);
        table.SetColumnWidthsPercentage(cards.Select(c => 1).ToArray());
        for (int index = 0; index < cards.Length; index++) {
            var card = cards[index];
            WordTableCell cell = table.Rows[0].Cells[index];
            style.ApplyValueCard(cell, card.Label, card.Value, card.Tone, style.Surface);
            cell.Paragraphs.Last().ColorHex = card.Tone;
        }
    }

    private static void WriteActions(WordDocument document, WordPaperStyle style, DomainAssessmentReport report, AssessmentWordOptions options) {
        // Start the overview after the dedicated contents page (or after the cover when disabled).
        Heading(document, style, "Do these first", 2, newPage: true);
        var all = Wording.DoFirst(report).ToList();
        var actions = all.Take(options.FixFirstCount).ToList();
        if (actions.Count == 0) {
            Body(document, style, all.Count == 0 ? "No checks need attention." : "Prioritized actions are in the domain chapters.");
            return;
        }
        WordTable table = document.AddTable(actions.Count, 2, WordTableStyle.TableNormal);
        for (int index = 0; index < actions.Count; index++) {
            var action = actions[index];
            style.SetCellText(table.Rows[index].Cells[0], Wording.OutcomeLabel(action.Check.Outcome));
            WordTableCell cell = table.Rows[index].Cells[1];
            // Keep the same message and source strings as HTML. The domain is a separate identifier run.
            style.SetCellText(cell, action.Check.Title);
            cell.Paragraphs[0].Bold = true;
            cell.AddParagraph(Identifier(action.Domain.Domain));
            cell.AddParagraph(Wording.DoFirstMessage(action.Check));
        }
        style.ApplyTable(table, hasHeader: false, allowRowSplit: false, alignNumericColumns: false);
        table.SetColumnWidthsPercentage(14, 86);
        for (int index = 0; index < actions.Count; index++) {
            WordTableCell text = table.Rows[index].Cells[1];
            text.Paragraphs[0].Bold = true;
            foreach (WordParagraph paragraph in text.Paragraphs) { paragraph.FontSizePoints = 10.5; }
            WordParagraph meta = text.Paragraphs[1];
            WordParagraph message = text.Paragraphs[2];
            meta.FontFamily = Mono;
            meta.ColorHex = style.Muted;
            WordParagraph source = meta.AddText(" · " + Wording.DoFirstSource(actions[index].Check));
            source.FontFamily = style.FontFamily;
            source.FontSizePoints = 10.5;
            source.ColorHex = style.Muted;
            text.Paragraphs[0].KeepWithNext = true;
            meta.KeepWithNext = true;
            message.LineSpacingAfterPoints = 6;
            style.ApplyCellTone(table.Rows[index].Cells[0], OutcomeTone(actions[index].Check.Outcome));
            table.Rows[index].Cells[0].Paragraphs[0].FontSizePoints = 10.5;
        }
        if (all.Count > actions.Count) {
            style.AddNote(document, "First " + Number(actions.Count) + " of " + Number(all.Count)
                + " prioritized actions shown; every result is in the domain chapters and All checks appendix.");
        }
    }

    private static void WriteAreas(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        Heading(document, style, "Area by area", 2);
        var groups = report.Domains.SelectMany(d => d.Checks).GroupBy(c => c.Area)
            .OrderBy(g => AreaIndex(g.Key)).ToList();
        if (groups.Count == 0) { Body(document, style, "No checks ran."); return; }
        var rows = new List<string[]>();
        foreach (var group in groups) {
            List<CheckAssessment> checks = group.ToList();
            int? score = AreaScore(report, group.Key, checks);
            rows.Add(new[] {
                Wording.AreaLabel(group.Key), AreaStatus(checks), Score(score), Number(checks.Count),
                Number(checks.Count(c => c.Outcome is CheckOutcome.Pass or CheckOutcome.Info)), Number(checks.Count(Wording.NeedsAttention))
            });
            rows.Add(new[] { Wording.AreaNote(report, checks), "", "", "", "", "" });
        }
        WordTable table = Table(document, style, new[] { "Area", "Status", "Score", "Checks", "Passing", "Needs attention" }, rows, 35, 18, 14, 9, 10, 14);
        for (int index = 0; index < groups.Count; index++) {
            List<CheckAssessment> checks = groups[index].ToList();
            WordTableRow main = table.Rows[index * 2 + 1];
            style.ApplyCellTone(main.Cells[1], AreaTone(checks));
            style.ApplyCellTone(main.Cells[2], ScoreTone(AreaScore(report, groups[index].Key, checks)));
            // A full-width quiet note retains the shared sentence without squeezing it into the Area column.
            WordTableRow note = table.Rows[index * 2 + 2];
            table.MergeCells(index * 2 + 2, 0, 1, 6);
            style.ApplyCellTone(note.Cells[0], style.Muted);
        }
    }

    private static int? AreaScore(DomainAssessmentReport report, AnalysisArea area, List<CheckAssessment> checks) {
        if (checks.Any(c => c.Scored && !c.EvidenceComplete)) { return null; }
        int[] scores = report.Domains.SelectMany(d => d.Areas).Where(a => a.Area == area && a.Score.HasValue)
            .Select(a => a.Score!.Value).ToArray();
        return scores.Length == 0 ? null : (int)Math.Round(scores.Average());
    }

    private static int AreaIndex(AnalysisArea area) {
        for (int index = 0; index < DomainAssessmentCatalog.AreaOrder.Count; index++) {
            if (DomainAssessmentCatalog.AreaOrder[index] == area) { return index; }
        }
        return int.MaxValue;
    }

    private static string AreaStatus(List<CheckAssessment> checks) => checks.Any(c => c.Outcome == CheckOutcome.Error) ? "Errors"
        : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? "Needs attention"
        : checks.Any(c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) ? "Incomplete"
        : checks.Any(c => c.Scored) ? "Passing" : "Informational";

    private static string AreaTone(List<CheckAssessment> checks) => checks.Any(c => c.Outcome == CheckOutcome.Error) ? High
        : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? Elevated
        : checks.Any(c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) || checks.All(c => !c.Scored) ? Neutral : Good;

    private static void WriteControls(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        Heading(document, style, "Controls", 2);
        var controls = Wording.Controls.ToList();
        string[] labels = new[] { "Domain" }.Concat(controls.Select(c => report.Domains.SelectMany(d => d.Checks)
            .FirstOrDefault(check => check.Key == c.Key)?.Title ?? (c.Key switch { "mtasts" => "MTA-STS", "tlsrpt" => "TLS-RPT", _ => c.Key.ToUpperInvariant() }))).ToArray();
        var rows = report.Domains.Select(domain => new[] { Identifier(domain.Domain) }.Concat(controls.Select(control => {
            CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == control.Key);
            return check?.Outcome switch { CheckOutcome.Pass => "pass", CheckOutcome.Warning => "warn", CheckOutcome.Error => "error", _ => "–" };
        })).ToArray());
        WordTable table = Table(document, style, labels, rows, new[] { 28 }.Concat(controls.Select(c => 8)).ToArray());
        for (int index = 0; index < report.Domains.Count; index++) {
            WordTableRow row = table.Rows[index + 1];
            MonoCell(row.Cells[0]);
            for (int column = 0; column < controls.Count; column++) {
                CheckAssessment? check = report.Domains[index].Checks.FirstOrDefault(c => c.Key == controls[column].Key);
                style.ApplyCellTone(row.Cells[column + 1], check == null ? Neutral : OutcomeTone(check.Outcome));
            }
        }
        style.AddNote(document, "A dash means the control is informational, incomplete or was not assessed. Status is carried by the text, not a cell fill.");
    }
}
