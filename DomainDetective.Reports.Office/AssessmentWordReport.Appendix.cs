using System.Collections.Generic;
using System.Linq;
using OfficeIMO.Word;
using OfficeIMO;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    private static void WriteAppendix(WordDocument document, WordPaperStyle style, DomainAssessmentReport report, AssessmentWordOptions options) {
        WordSection allChecks = document.AddSection(WordSectionBreakType.NextPage);
        allChecks.PageSetup.Orientation = OfficePageOrientation.Landscape;
        allChecks.PageSetup.DifferentFirstPage = false;
        Heading(document, style, "Appendix", 1);
        Heading(document, style, "All checks", 2);
        var checks = report.Domains.SelectMany(domain => domain.Checks.OrderBy(check => AreaIndex(check.Area))
            .Select(check => (Domain: domain, Check: check))).ToList();
        if (checks.Count == 0) { Body(document, style, "No checks ran."); }
        else {
            WordTable table = Table(document, style, new[] {
                "Domain", "Area", "Check", "Outcome", "Key number", "Score", "Errors", "Warnings", "Top finding", "Summary"
            }, checks.Select(row => new[] {
                Identifier(row.Domain.Domain), Wording.AreaLabel(row.Check.Area), row.Check.Title, Wording.OutcomeLabel(row.Check.Outcome),
                HeadlineText(row.Check), row.Check.Scored ? Score(row.Check.Score) : "Not scored", Number(row.Check.ErrorCount), Number(row.Check.WarningCount),
                Wording.TopFinding(row.Check) ?? string.Empty,
                row.Check.Summary ?? row.Check.Description ?? string.Empty
            }), 13, 6, 9, 9, 11, 7, 6, 7, 16, 16);
            for (int index = 0; index < checks.Count; index++) {
                WordTableRow row = table.Rows[index + 1];
                MonoCell(row.Cells[0]);
                style.ApplyCellTone(row.Cells[3], OutcomeTone(checks[index].Check.Outcome));
                if (!checks[index].Check.Scored || !checks[index].Check.Score.HasValue) { style.ApplyCellTone(row.Cells[5], Neutral); }
                if (checks[index].Check.ErrorCount == 0) { style.ApplyCellTone(row.Cells[6], Neutral); }
                if (checks[index].Check.WarningCount == 0) { style.ApplyCellTone(row.Cells[7], Neutral); }
            }
        }
        Heading(document, style, "How scoring works", 2);
        WordTable scoring = style.AddKeyValueTable(document, Wording.ScoringFacts.Concat(new[] {
            new KeyValuePair<string, string>("This run", Wording.ScoreNote(report)),
            new KeyValuePair<string, string>("Generated", Wording.FormatTime(report.GeneratedAtUtc))
        }), allowRowSplit: true);
        scoring.SetColumnWidthsPercentage(22, 78);
        SizeTable(scoring);
        if (report.UnassignedInputs.Count > 0) {
            Heading(document, style, "Inputs without a domain", 2);
            Body(document, style, "These inputs did not name a domain and are not included in the domain chapters.");
            WordTable inputs = style.AddKeyValueTable(document, report.UnassignedInputs.GroupBy(name => name)
                .Select(g => new KeyValuePair<string, string>(g.Key, Number(g.Count()))), "Input type", "Count");
            SizeTable(inputs);
        }
        WriteRawRecords(document, style, report);
        WriteTableEvidence(document, style, report);
        WriteSupplementaryEvidence(document, style, report, options);
    }

    private static void WriteRawRecords(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        var records = report.Domains.SelectMany(domain => domain.Checks.SelectMany(check => check.Evidence
            .Where(e => e.Kind == CheckEvidenceKind.Code).Select(e => (Domain: domain, Check: check, Evidence: e)))).ToList();
        if (records.Count == 0) { return; }
        Heading(document, style, "Raw records", 2);
        foreach (var group in records.GroupBy(record => (record.Check.Key, record.Evidence.Title))) {
            Heading(document, style, group.First().Check.Title + " · " + group.Key.Title, 3);
            WordTable table = style.AddKeyValueTable(document, group.Select(record =>
                new KeyValuePair<string, string>(Identifier(record.Domain.Domain), record.Evidence.Text ?? string.Empty)),
                "Domain", "Published record", allowRowSplit: true);
            table.SetColumnWidthsPercentage(28, 72);
            SizeTable(table);
            foreach (WordTableRow row in table.Rows.Skip(1)) {
                MonoCell(row.Cells[0]);
                MonoCell(row.Cells[1]);
            }
            foreach (var record in group.Where(record => record.Evidence.Omitted > 0)) {
                Body(document, style, record.Domain.Domain + " · " + record.Check.Title);
                OmissionNote(document, style, record.Evidence);
            }
        }
    }

    private static void WriteTableEvidence(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        var evidence = report.Domains.SelectMany(domain => domain.Checks.SelectMany(check => check.Evidence
            .Where(e => e.Kind == CheckEvidenceKind.Table).Select(e => (Domain: domain, Check: check, Evidence: e)))).ToList();
        if (evidence.Count == 0) { return; }
        Heading(document, style, "Table evidence", 2);
        // Keep one table for each captured schema, with domain attribution on every row.
        foreach (var group in evidence.GroupBy(item => (item.Check.Key, item.Evidence.Title, Schema: string.Join("\u001F", item.Evidence.Columns)))) {
            var first = group.First();
            Heading(document, style, first.Check.Title + " · " + first.Evidence.Title, 3);
            string[] headers = new[] { "Domain" }.Concat(first.Evidence.Columns).ToArray();
            WordTable table = Table(document, style, headers,
                group.SelectMany(item => item.Evidence.Rows.Select(row => new[] { Identifier(item.Domain.Domain) }.Concat(row).ToArray())));
            foreach (WordTableRow row in table.Rows.Skip(1)) {
                foreach (WordTableCell cell in row.Cells) { IdentifierValueCell(cell); }
            }
            foreach (var item in group.Where(item => item.Evidence.Omitted > 0)) {
                Body(document, style, item.Domain.Domain + " · " + item.Check.Title);
                OmissionNote(document, style, item.Evidence);
            }
        }
    }
}
