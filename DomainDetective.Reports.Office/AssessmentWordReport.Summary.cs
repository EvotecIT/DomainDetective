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
        rule.Borders.BottomColor = OfficeColor.Parse(style.Accent);
        rule.Borders.BottomSize = OfficeLength.Points(3);
        int attention = checks.Count(Wording.NeedsAttention);
        int errors = checks.Count(c => c.Outcome == CheckOutcome.Error);
        int incomplete = checks.Count(c => !c.EvidenceComplete);
        string tone = errors > 0 ? High : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? Elevated : attention > 0 ? Neutral : Good;
        // The verdict sits in a toned panel: the shared sentence, its detail and, for one domain, the risk verdict.
        var lines = new List<string> { Wording.ReportVerdictDetail(report) };
        if (report.Domains.Count == 1 && report.Domains[0].RiskProfile is { } profile) {
            lines.Add("Risk: " + Wording.RiskValue(profile) + ". " + Wording.RiskVerdict(profile));
        }
        Panel(document, style, Wording.ReportVerdict(report), lines, tone);
        Cards(document, style, new (string Label, string Value, string Tone, string? Note)[] {
            ("Grade / score", report.Score.HasValue ? report.Grade + " · " + Score(report.Score) : "Not scored", ScoreTone(report.Score), Judged(report.Coverage)),
            ("Checks needing attention", Number(attention), errors > 0 ? High : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? Elevated : Neutral, null),
            ("Errors", Number(errors), errors > 0 ? High : Neutral, null),
            (Wording.OutcomeLabel(CheckOutcome.Incomplete), Number(incomplete), Neutral, null)
        });
    }

    /// <summary>"85% of checks judged" when part of the scored evidence was incomplete; otherwise null.</summary>
    private static string? Judged(double? coverage) => OfficeScoreText.Partial(coverage)
        ? OfficeScoreText.Percent(coverage!.Value) + " of checks judged" : null;

    /// <summary>A shaded block with a toned left rule: a bold lead sentence and quieter supporting lines.</summary>
    private static void Panel(WordDocument document, WordPaperStyle style, string lead, IEnumerable<string> lines, string tone) {
        var paragraphs = new List<WordParagraph> { Body(document, style, lead, true) };
        paragraphs[0].FontSize = OfficeLength.Points(11.5);
        foreach (string line in lines) {
            WordParagraph paragraph = Body(document, style, line);
            paragraph.Color = OfficeColor.Parse(style.Muted);
            paragraphs.Add(paragraph);
        }
        for (int index = 0; index < paragraphs.Count; index++) {
            WordParagraph paragraph = paragraphs[index];
            paragraph.ShadingFillColor = OfficeColor.Parse(Tint(tone));
            paragraph.Borders.LeftStyle = WordBorderStyle.Single;
            paragraph.Borders.LeftSize = OfficeLength.Points(4);
            paragraph.Borders.LeftColor = OfficeColor.Parse(tone);
            paragraph.Borders.LeftSpace = OfficeLength.Points(8);
            paragraph.IndentationBefore = OfficeLength.Points(10);
            paragraph.IndentationAfter = OfficeLength.Points(4);
            // No spacing inside the panel, so its shading and rule run unbroken; the last line pads the bottom.
            paragraph.LineSpacingBefore = OfficeLength.Points(index == 0 ? 10 : 0);
            paragraph.LineSpacingAfter = OfficeLength.Points(index == paragraphs.Count - 1 ? 12 : 0);
            paragraph.KeepWithNext = index < paragraphs.Count - 1;
        }
    }

    private static void Cards(WordDocument document, WordPaperStyle style, IEnumerable<(string Label, string Value, string Tone, string? Note)> values) {
        var cards = values.ToArray();
        if (cards.Length == 0) { return; }
        WordTable table = document.AddTable(1, cards.Length, WordTableStyle.TableNormal);
        style.ApplyTable(table, hasHeader: false);
        table.SetColumnWidthsPercentage(cards.Select(c => 1).ToArray());
        for (int index = 0; index < cards.Length; index++) {
            var card = cards[index];
            WordTableCell cell = table.Rows[0].Cells[index];
            style.ApplyValueCard(cell, card.Label, card.Value, card.Tone, style.Surface);
            cell.Paragraphs.Last().Color = OfficeColor.Parse(card.Tone);
            if (card.Note != null) {
                WordParagraph note = cell.AddParagraph(card.Note);
                note.FontFamily = style.FontFamily;
                note.FontSize = OfficeLength.Points(8);
                note.Color = OfficeColor.Parse(style.Muted);
                note.LineSpacingBefore = OfficeLength.Points(1);
                note.LineSpacingAfter = OfficeLength.Points(0);
            }
        }
    }

    private static void WriteActions(WordDocument document, WordPaperStyle style, DomainAssessmentReport report, AssessmentWordOptions options) {
        Heading(document, style, "Do these first", 2);
        var all = Wording.DoFirstGroups(report).ToList();
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
            cell.AddParagraph(Identifier(action.AffectedDomains));
            cell.AddParagraph(Wording.DoFirstMessage(action.Check));
        }
        style.ApplyTable(table, hasHeader: false, allowRowSplit: false, alignNumericColumns: false);
        table.SetColumnWidthsPercentage(14, 86);
        for (int index = 0; index < actions.Count; index++) {
            string tone = OutcomeTone(actions[index].Check.Outcome);
            WordTableCell status = table.Rows[index].Cells[0];
            WordTableCell text = table.Rows[index].Cells[1];
            // Each action reads as a callout: a toned rule and pale tone behind the status, a quiet surface behind the
            // text, and white space between items instead of hairlines.
            status.ShadingFillColor = OfficeColor.Parse(Tint(tone));
            text.ShadingFillColor = OfficeColor.Parse(style.Surface);
            status.Borders.LeftStyle = WordBorderStyle.Single;
            status.Borders.LeftSize = OfficeLength.Points(4);
            status.Borders.LeftColor = OfficeColor.Parse(tone);
            foreach (WordTableCell cell in new[] { status, text }) {
                cell.Borders.BottomStyle = WordBorderStyle.Single;
                cell.Borders.BottomSize = OfficeLength.Points(6);
                cell.Borders.BottomColor = OfficeColor.Parse("FFFFFF");
                cell.MarginTop = OfficeLength.Points(4);
                cell.MarginLeft = OfficeLength.Points(7);
            }
            text.Paragraphs[0].Bold = true;
            foreach (WordParagraph paragraph in text.Paragraphs) { paragraph.FontSize = OfficeLength.Points(10.5); }
            WordParagraph meta = text.Paragraphs[1];
            WordParagraph message = text.Paragraphs[2];
            meta.FontFamily = report.Domains.Count == 1 ? Mono : style.FontFamily;
            meta.Color = OfficeColor.Parse(style.Muted);
            WordParagraph source = meta.AddText(" · " + Wording.DoFirstSource(actions[index].Check));
            source.FontFamily = style.FontFamily;
            source.FontSize = OfficeLength.Points(10.5);
            source.Color = OfficeColor.Parse(style.Muted);
            text.Paragraphs[0].KeepWithNext = true;
            meta.KeepWithNext = true;
            message.LineSpacingAfter = OfficeLength.Points(6);
            style.ApplyCellTone(status, tone);
            status.Paragraphs[0].FontSize = OfficeLength.Points(10.5);
            status.Paragraphs[0].Bold = true;
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
            (int? score, double? coverage) = OfficeScoreText.Area(checks);
            rows.Add(new[] {
                Wording.AreaLabel(group.Key), AreaStatus(checks), OfficeScoreText.Score(score, coverage), Number(checks.Count),
                Number(checks.Count(c => c.Scored && c.Outcome == CheckOutcome.Pass)), Number(checks.Count(Wording.NeedsAttention))
            });
            rows.Add(new[] { Wording.AreaNote(report, checks), "", "", "", "", "" });
        }
        WordTable table = Table(document, style, new[] { "Area", "Status", "Score", "Checks", "Passing", "Needs attention" }, rows, 22, 18, 28, 9, 10, 13);
        for (int index = 0; index < groups.Count; index++) {
            List<CheckAssessment> checks = groups[index].ToList();
            WordTableRow main = table.Rows[index * 2 + 1];
            main.Cells[0].Paragraphs[0].Bold = true;
            style.ApplyCellTone(main.Cells[1], AreaTone(checks));
            style.ApplyCellTone(main.Cells[2], ScoreTone(OfficeScoreText.Area(checks).Score));
            // A full-width quiet note retains the shared sentence without squeezing it into the Area column.
            WordTableRow note = table.Rows[index * 2 + 2];
            table.MergeCells(index * 2 + 2, 0, 1, 6);
            style.ApplyCellTone(note.Cells[0], style.Muted);
            main.Cells[0].Paragraphs[0].KeepWithNext = true;
        }
    }

    private static int AreaIndex(AnalysisArea area) {
        for (int index = 0; index < DomainAssessmentCatalog.AreaOrder.Count; index++) {
            if (DomainAssessmentCatalog.AreaOrder[index] == area) { return index; }
        }
        return int.MaxValue;
    }

    private static string AreaStatus(List<CheckAssessment> checks) => checks.Any(c => c.Outcome == CheckOutcome.Error) ? "Errors"
        : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? "Needs attention"
        : checks.Any(c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) ? Wording.OutcomeLabel(CheckOutcome.Incomplete)
        : checks.Any(c => c.Scored) ? "Passing" : "Informational";

    private static string AreaTone(List<CheckAssessment> checks) => checks.Any(c => c.Outcome == CheckOutcome.Error) ? High
        : checks.Any(c => c.Outcome == CheckOutcome.Warning) ? Elevated
        : checks.Any(c => !c.EvidenceComplete || c.Outcome == CheckOutcome.Incomplete) || checks.All(c => !c.Scored) ? Neutral : Good;

    private static void WriteControls(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        Heading(document, style, "Controls", 2);
        var controls = Wording.ControlChecks(report).ToList();
        bool hasDash = report.Domains.Any(domain => controls.Any(control => domain.Checks.FirstOrDefault(check => check.Key == control.Key)?.Outcome
            is not (CheckOutcome.Pass or CheckOutcome.Warning or CheckOutcome.Error)));
        // Repeat domains in bounded column groups so full outcome words remain readable on portrait paper.
        for (int offset = 0; offset < controls.Count; offset += 6) {
            var columns = controls.Skip(offset).Take(6).ToList();
            string[] labels = new[] { "Domain" }.Concat(columns.Select(check => check.Title)).Concat(Enumerable.Repeat(string.Empty, 6 - columns.Count)).ToArray();
            var rows = report.Domains.Select(domain => new[] { Identifier(domain.Domain) }.Concat(columns.Select(control => {
                CheckAssessment? check = domain.Checks.FirstOrDefault(c => c.Key == control.Key);
                return check?.Outcome is CheckOutcome.Pass or CheckOutcome.Warning or CheckOutcome.Error ? Wording.OutcomeLabel(check.Outcome) : "–";
            })).ToArray());
            int[] widths = new[] { 28 }.Concat(Enumerable.Repeat(12, 6)).ToArray();
            if (offset > 0) {
                // A little air, so the next group's header does not read as a row of the previous table.
                WordParagraph gap = document.AddParagraph(string.Empty);
                gap.LineSpacingBefore = OfficeLength.Points(0);
                gap.LineSpacingAfter = OfficeLength.Points(0);
                gap.FontSize = OfficeLength.Points(6);
            }
            WordTable table = Table(document, style, labels, rows, widths);
            table.SetColumnWidthsPercentage(widths);
            for (int index = 0; index < report.Domains.Count; index++) {
                WordTableRow row = table.Rows[index + 1];
                MonoCell(row.Cells[0]);
                for (int column = 0; column < columns.Count; column++) {
                    CheckAssessment? check = report.Domains[index].Checks.FirstOrDefault(c => c.Key == columns[column].Key);
                    style.ApplyCellTone(row.Cells[column + 1], check == null ? Neutral : OutcomeTone(check.Outcome));
                }
            }
        }
        if (hasDash) {
            style.AddNote(document, "A dash means the control is informational, incomplete or was not assessed. Status is carried by the text, not a cell fill.");
        }
    }
}
