using System.Collections.Generic;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Word;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentWordReport {
    /// <summary>The risk profile block at the start of a domain chapter.</summary>
    private static void WriteRiskProfile(WordDocument document, WordPaperStyle style, DomainAssessment domain) {
        DomainRiskProfile? profile = domain.RiskProfile;
        if (profile == null) { return; }
        Heading(document, style, "Risk profile", 2);
        Cards(document, style, new[] {
            (Label: "Risk", Value: Wording.RiskValue(profile), Tone: RiskTone(profile)),
            (Label: "Confidence", Value: Wording.ConfidenceValue(profile), Tone: Neutral),
            (Label: "Posture", Value: domain.Score.HasValue ? domain.Grade + " · " + Score(domain.Score) : "Not scored", Tone: ScoreTone(domain.Score))
        });
        Body(document, style, Wording.RiskVerdict(profile) + (Wording.ConfidenceNote(profile) is { } note ? " " + note : string.Empty));

        List<RiskSignal> signals = Wording.ShownSignals(profile).ToList();
        if (signals.Count > 0) {
            WordTable table = Table(document, style, new[] { "Points", "Why" },
                signals.Select(s => new[] { Wording.Points(s.Points), s.Reason + " · " + Wording.SignalSource(s) }), 12, 88);
            for (int index = 0; index < signals.Count; index++) {
                style.ApplyCellTone(table.Rows[index + 1].Cells[0], signals[index].Points < 0 ? Good : signals[index].Points >= 20 || signals[index].Decisive ? High : Elevated);
            }
        }

        WordTable facets = Table(document, style, new[] { "Area", "Coverage", "Missing or partial evidence" },
            profile.Facets.Select(f => new[] { Wording.FacetLabel(f.Kind), Wording.FacetCoverage(f), Wording.FacetEvidence(f) }), 18, 14, 68);
        for (int index = 0; index < profile.Facets.Count; index++) {
            ProfileFacet facet = profile.Facets[index];
            if (!facet.Counted || facet.Coverage < 1) { style.ApplyCellTone(facets.Rows[index + 1].Cells[1], Neutral); }
        }

        List<ProfileFact> facts = profile.Facets.SelectMany(f => f.Facts).ToList();
        if (facts.Count > 0) {
            WordTable known = style.AddKeyValueTable(document, facts.Select(f =>
                new KeyValuePair<string, string>(f.Label, string.IsNullOrWhiteSpace(f.Note) ? f.Value : f.Value + " · " + f.Note)), allowRowSplit: true, hasHeader: false);
            known.SetColumnWidthsPercentage(32, 68);
            SizeTable(known);
        }

        List<EvidenceGap> gaps = Wording.TopGaps(profile).ToList();
        if (gaps.Count > 0) {
            Note(document, style, "What would raise confidence: " + string.Join("; ", gaps.Select(Wording.GapLine)) + ".");
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
            style.ApplyCellTone(table.Rows[index + 1].Cells[1], RiskTone(profiled[index].RiskProfile!));
            style.ApplyCellTone(table.Rows[index + 1].Cells[3], ScoreTone(profiled[index].Score));
        }
    }

    private static string RiskTone(DomainRiskProfile profile) => !profile.Rated ? Neutral : profile.RiskLevel switch {
        DomainRiskLevel.Critical or DomainRiskLevel.High => High,
        DomainRiskLevel.Medium => Elevated,
        DomainRiskLevel.Low => Neutral,
        _ => profile.Confidence == EvidenceConfidence.High ? Good : Neutral
    };
}
