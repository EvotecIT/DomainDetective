using System.Collections.Generic;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    /// <summary>
    /// The risk profile block at the start of a domain chapter: risk, confidence and posture cards, the verdict panel,
    /// the signals that moved the score, evidence coverage per area, the known facts and what would raise confidence.
    /// </summary>
    private static void WriteRiskProfile(WordDocument document, WordPaperStyle style, DomainAssessment domain) {
        DomainRiskProfile? profile = domain.RiskProfile;
        if (profile == null) { return; }
        Heading(document, style, "Risk profile", 2);
        Cards(document, style, new (string Label, string Value, string Tone, string? Note)[] {
            ("Risk", Wording.RiskValue(profile), RiskTone(profile), profile.Rated ? null : "Not rated"),
            ("Confidence", Wording.ConfidenceValue(profile), Neutral, null),
            ("Posture", domain.Score.HasValue ? domain.Grade + " · " + Score(domain.Score) : "Not scored", ScoreTone(domain.Score), Judged(domain.Coverage))
        });
        Panel(document, style, Wording.RiskVerdict(profile), Wording.ConfidenceNote(profile) is { } note ? new[] { note } : new string[0], RiskTone(profile));

        List<RiskSignal> signals = Wording.ShownSignals(profile).ToList();
        if (signals.Count > 0) {
            Heading(document, style, "Signals", 3);
            WordTable table = Table(document, style, new[] { "Counts", "Why", "Source" },
                signals.Select(s => new[] { s.Points < 0 ? "In favour" : "Against", s.Reason, Wording.SignalSource(s) }), 14, 58, 28);
            for (int index = 0; index < signals.Count; index++) {
                string tone = signals[index].Points < 0 ? Good : signals[index].Points >= 20 || signals[index].Decisive ? High : Elevated;
                style.ApplyCellTone(table.Rows[index + 1].Cells[0], tone);
                table.Rows[index + 1].Cells[0].Paragraphs[0].Bold = true;
                style.ApplyCellTone(table.Rows[index + 1].Cells[2], style.Muted);
            }
        }

        Heading(document, style, "Evidence coverage", 3);
        WordTable facets = Table(document, style, new[] { "Area", "Coverage", "Missing or partial evidence" },
            profile.Facets.Select(f => new[] { Wording.FacetLabel(f.Kind), Wording.FacetCoverage(f), Wording.FacetEvidence(f) }), 18, 14, 68);
        for (int index = 0; index < profile.Facets.Count; index++) {
            ProfileFacet facet = profile.Facets[index];
            WordTableRow row = facets.Rows[index + 1];
            row.Cells[0].Paragraphs[0].Bold = true;
            style.ApplyCellTone(row.Cells[1], !facet.Counted || facet.Coverage < 1 ? Neutral : Good);
            if (facet.Counted && facet.Coverage >= 1) { style.ApplyCellTone(row.Cells[2], style.Muted); }
        }

        List<ProfileFact> facts = profile.Facets.SelectMany(f => f.Facts).ToList();
        if (facts.Count > 0) {
            Heading(document, style, "What is known", 3);
            WordTable known = style.AddKeyValueTable(document, facts.Select(f =>
                new KeyValuePair<string, string>(f.Label, string.IsNullOrWhiteSpace(f.Note) ? f.Value : f.Value + " · " + f.Note)),
                "Fact", "Value", allowRowSplit: true);
            known.SetColumnWidthsPercentage(28, 72);
            SizeTable(known);
            foreach (WordTableRow row in known.Rows.Skip(1)) { IdentifierValueCell(row.Cells[1]); }
        }

        List<EvidenceGap> gaps = Wording.TopGaps(profile).ToList();
        if (gaps.Count > 0) {
            Advice(document, style, "What would raise confidence", string.Join("; ", gaps.Select(Wording.GapLine)) + ".");
        }
    }

    /// <summary>Several domains: risk and confidence per domain, riskiest first.</summary>
    private static void WriteRiskSummary(WordDocument document, WordPaperStyle style, DomainAssessmentReport report) {
        List<DomainAssessment> profiled = Wording.RiskOrder(report).ToList();
        if (profiled.Count == 0) { return; }
        Heading(document, style, "Risk by domain", 2);
        WordTable table = Table(document, style, new[] { "Domain", "Risk", "Confidence", "Posture", "Top signal" },
            profiled.Select(d => new[] {
                Identifier(d.Domain), Wording.RiskValue(d.RiskProfile!), Wording.ConfidenceValue(d.RiskProfile!),
                d.Score.HasValue ? d.Grade : "Not scored",
                Wording.ShownSignals(d.RiskProfile!).FirstOrDefault()?.Reason ?? Wording.RiskVerdict(d.RiskProfile!)
            }), 26, 14, 16, 10, 34);
        for (int index = 0; index < profiled.Count; index++) {
            MonoCell(table.Rows[index + 1].Cells[0]);
            style.ApplyCellTone(table.Rows[index + 1].Cells[1], RiskTone(profiled[index].RiskProfile!));
            table.Rows[index + 1].Cells[1].Paragraphs[0].Bold = true;
            style.ApplyCellTone(table.Rows[index + 1].Cells[3], ScoreTone(profiled[index].Score));
        }
        List<DomainAssessment> gapped = profiled.Where(d => Wording.TopGaps(d.RiskProfile!).Any()).ToList();
        if (gapped.Count > 0) {
            // Every domain shares the same collection setup, so one line usually covers them all.
            var lines = gapped.Select(d => string.Join("; ", Wording.TopGaps(d.RiskProfile!).Select(Wording.GapLine))).Distinct().ToList();
            Advice(document, style, "What would raise confidence", lines.Count == 1 ? lines[0] + "."
                : string.Join(" ", gapped.Select(d => d.Domain + ": " + string.Join("; ", Wording.TopGaps(d.RiskProfile!).Select(Wording.GapLine)) + ".")));
        }
    }

    private static string RiskTone(DomainRiskProfile profile) => !profile.Rated ? Neutral : profile.RiskLevel switch {
        DomainRiskLevel.Critical or DomainRiskLevel.High => High,
        DomainRiskLevel.Medium => Elevated,
        DomainRiskLevel.Low => Neutral,
        _ => profile.Confidence == EvidenceConfidence.High ? Good : Neutral
    };
}
