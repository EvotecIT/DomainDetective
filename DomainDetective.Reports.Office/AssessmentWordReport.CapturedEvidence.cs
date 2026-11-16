using System;
using System.Linq;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    private static void WriteSupplementaryEvidence(WordDocument document, WordPaperStyle style,
        DomainAssessmentReport report, AssessmentWordOptions options) {
        // Attention blocks already print these values. Finding visibility must not hide evidence from other checks.
        var checks = report.Domains.SelectMany(domain => domain.Checks
            .Where(check => !Wording.NeedsAttention(check) && !(options.ShowInfoFindings && check.Findings.Count > 0))
            .Select(check => (Domain: domain, Check: check))).ToList();
        var facts = checks.SelectMany(item => item.Check.Facts
            // The domain column already preserves an identical subject value.
            .Where(fact => !(fact.Label == "Subject" && string.Equals(fact.Value, item.Domain.Domain, StringComparison.OrdinalIgnoreCase)))
            .Select(fact => (item.Domain, item.Check, Fact: fact))).ToList();
        if (facts.Count > 0) {
            Heading(document, style, "Additional facts", 2);
            foreach (var group in facts.GroupBy(item => item.Check.Key)) {
                Heading(document, style, group.First().Check.Title, 3);
                WordTable table = Table(document, style, new[] { "Domain", "Field", "Value" }, group.Select(item =>
                    new[] { Identifier(item.Domain.Domain), item.Fact.Label, item.Fact.Value }), 28, 24, 48);
                foreach (WordTableRow row in table.Rows.Skip(1)) { IdentifierValueCell(row.Cells[2]); }
            }
        }
        var lists = checks.SelectMany(item => item.Check.Evidence.Where(evidence => evidence.Kind == CheckEvidenceKind.List)
            .Select(evidence => (item.Domain, item.Check, Evidence: evidence)));
        foreach (var group in lists.GroupBy(item => (item.Check.Key, item.Evidence.Title))) {
            Heading(document, style, group.First().Check.Title + " · " + group.Key.Title, 3);
            var values = group.SelectMany(item => item.Evidence.Items.Select(value => new[] { Identifier(item.Domain.Domain), value })).ToList();
            WordTable table = Table(document, style, new[] { "Domain", "Value" }, values.Take(TableEvidenceRows), 28, 72);
            foreach (WordTableRow row in table.Rows.Skip(1)) { IdentifierValueCell(row.Cells[1]); }
            if (values.Count > TableEvidenceRows) {
                Note(document, style, "First " + Number(TableEvidenceRows) + " of " + Number(values.Count)
                    + " shown; all " + Number(values.Count) + " are on the Evidence sheet of the Excel workbook.");
            }
            foreach (var item in group.Where(item => item.Evidence.Omitted > 0)) {
                Body(document, style, item.Domain.Domain);
                OmissionNote(document, style, item.Evidence);
            }
        }
    }
}
