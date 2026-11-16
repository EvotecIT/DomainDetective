using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    /// <summary>One risk sheet: the verdict per domain, then every signal, then every evidence item behind the confidence.</summary>
    private static void WriteRiskProfiles(ExcelSheet sheet, List<DomainAssessment> domains) {
        bool several = domains.Count > 1;
        Title(sheet, "Risk profile · " + (several ? Wording.Plural(domains.Count, "domain") : domains[0].Domain), Wording.RiskScaleNote);
        int row = 3;

        row += 1;
        int header = row;
        WriteHeader(sheet, header, "Domain", "Risk", "Score", "Confidence", "Posture", "Verdict", "Top signals");
        foreach (DomainAssessment domain in domains) {
            DomainRiskProfile profile = domain.RiskProfile!;
            WriteRow(sheet, ++row, domain.Domain, profile.Rated ? Wording.RiskLevelLabel(profile.RiskLevel) : Wording.RiskWord(profile), profile.Rated ? (object?)profile.RiskScore : null,
                Wording.ConfidenceValue(profile), OfficeScoreText.Graded(domain.Grade, domain.Score, domain.Coverage),
                Wording.RiskVerdict(profile) + (Wording.ConfidenceNote(profile) is { } note ? " " + note : string.Empty),
                string.Join("; ", Wording.ShownSignals(profile).Take(3).Select(static s => s.Reason)));
            sheet.Cell(row, 1).SetFontFamily(Mono);
            Tone(sheet, row, 2, RiskColor(profile));
            if (profile.Confidence == EvidenceConfidence.Low) { sheet.Cell(row, 4).SetColor(OfficeColor.Parse(Muted)); }
            sheet.Cell(row, 5).SetColor(OfficeColor.Parse(ScoreTone(domain.Score)));
        }
        Table(sheet, "RiskProfile", header, row, 7, 26, 20, 10, 16, 24, 70, 60);
        Wrap(sheet, header + 1, row, 6, 7);
        WriteCell(sheet, ++row, 1, "Rules " + string.Join(", ", domains.Select(static d => d.RiskProfile!.RuleVersion).Distinct()) + ".")
            .SetColor(OfficeColor.Parse(Muted)).SetFontSize(OfficeLength.Points(8));

        row += 2;
        WriteCell(sheet, row, 1, "Signals").SetBold().SetFontSize(OfficeLength.Points(11));
        header = ++row;
        WriteHeader(sheet, header, "Domain", "Area", "Points", "Source", "Check", "Why", "Holds the level");
        foreach (DomainAssessment domain in domains) {
            foreach (RiskSignal signal in domain.RiskProfile!.Signals) {
                WriteRow(sheet, ++row, domain.Domain, Wording.FacetLabel(signal.Facet), signal.Points, signal.Source,
                    CheckTitle(domain, signal.CheckKey), signal.Reason, signal.Decisive ? "Yes" : null);
                sheet.Cell(row, 1).SetFontFamily(Mono);
                Tone(sheet, row, 3, signal.Points < 0 ? Good : signal.Points >= 20 || signal.Decisive ? High : signal.Points == 0 ? Muted : Elevated);
            }
        }
        if (row == header) { WriteCell(sheet, ++row, 1, "No risk signals were observed."); }
        Table(sheet, "RiskSignals", header, row, 7);
        Wrap(sheet, header + 1, row, 6);

        row += 2;
        WriteCell(sheet, row, 1, "Evidence behind the confidence").SetBold().SetFontSize(OfficeLength.Points(11));
        header = ++row;
        WriteHeader(sheet, header, "Domain", "Area", "Confidence gain", "State", "Source", "Evidence", "Note");
        foreach (DomainAssessment domain in domains) {
            DomainRiskProfile profile = domain.RiskProfile!;
            var gains = profile.Gaps.GroupBy(static g => g.EvidenceId).ToDictionary(static g => g.Key, static g => g.First().ConfidenceGain);
            foreach (ProfileFacet facet in profile.Facets) {
                foreach (EvidenceItem item in facet.Evidence) {
                    WriteRow(sheet, ++row, domain.Domain, Wording.FacetLabel(facet.Kind) + (facet.Counted ? " · " + Wording.FacetCoverage(facet) : " · not counted"),
                        gains.TryGetValue(item.Id, out double gain) ? (object?)gain : null, Wording.EvidenceStateLabel(item.State), item.Source,
                        item.Label, item.Note);
                    sheet.Cell(row, 1).SetFontFamily(Mono);
                    if (item.State is not (EvidenceState.Observed or EvidenceState.Clean)) { sheet.Cell(row, 4).SetColor(OfficeColor.Parse(Muted)); }
                    if (gains.ContainsKey(item.Id)) { sheet.Cell(row, 3).SetNumberFormat("+0.00"); }
                }
            }
        }
        Table(sheet, "RiskEvidence", header, row, 7);
        Wrap(sheet, header + 1, row, 6, 7);
        Paper(sheet, 0, 0, Tabs[2]);
    }

    private static string? CheckTitle(DomainAssessment domain, string? key) => key == null ? null
        : domain.Checks.FirstOrDefault(c => c.Key == key)?.Title;

    private static string RiskColor(DomainRiskProfile profile) => !profile.Rated ? Muted : profile.RiskLevel switch {
        DomainRiskLevel.Critical or DomainRiskLevel.High => High,
        DomainRiskLevel.Medium => Elevated,
        DomainRiskLevel.Low => Muted,
        _ => profile.Confidence == EvidenceConfidence.High ? Good : Muted
    };
}
