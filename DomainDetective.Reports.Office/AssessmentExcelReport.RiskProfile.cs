using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using DomainDetective.Profiles;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    /// <summary>Writes the risk profile sheets when any domain has a profile.</summary>
    private static void WriteRiskProfiles(ExcelDocument workbook, DomainAssessmentReport report) {
        List<DomainAssessment> profiled = Wording.RiskOrder(report).ToList();
        if (profiled.Count == 0) { return; }
        WriteRiskSummary(workbook.AddSheet("Risk profile"), profiled);
        WriteRiskSignals(workbook.AddSheet("Risk signals"), profiled);
        WriteRiskCoverage(workbook.AddSheet("Evidence coverage"), profiled);
    }

    private static void WriteRiskSummary(ExcelSheet sheet, List<DomainAssessment> domains) {
        WriteRow(sheet, 1, "Risk profile");
        sheet.Cell(1, 1).SetBold();
        WriteRow(sheet, 2, Wording.RiskScaleNote);
        sheet.Cell(2, 1).SetColor(OfficeColor.Parse(Muted));
        const int header = 4;
        WriteHeader(sheet, header, "Domain", "Risk score", "Risk level", "Rated", "Confidence", "Confidence score", "Posture", "Verdict", "Top signals", "Rules");
        int row = header;
        foreach (DomainAssessment domain in domains) {
            DomainRiskProfile profile = domain.RiskProfile!;
            WriteRow(sheet, ++row, domain.Domain, profile.RiskScore, Wording.RiskLevelLabel(profile.RiskLevel), profile.Rated ? "Yes" : "No",
                Wording.ConfidenceLabel(profile.Confidence), profile.ConfidenceScore, domain.Score.HasValue ? domain.Grade : "Not scored",
                Wording.RiskVerdict(profile) + (Wording.ConfidenceNote(profile) is { } note ? " " + note : string.Empty),
                string.Join("; ", Wording.ShownSignals(profile).Take(3).Select(static s => s.Reason)), profile.RuleVersion);
            sheet.Cell(row, 1).SetFontFamily("Consolas");
            sheet.Cell(row, 3).SetColor(OfficeColor.Parse(RiskColor(profile)));
            if (!profile.Rated) { sheet.Cell(row, 2).SetColor(OfficeColor.Parse(Muted)); }
            if (profile.Confidence == EvidenceConfidence.Low) { sheet.Cell(row, 5).SetColor(OfficeColor.Parse(Muted)); }
        }
        FinishSheet(sheet, header, row, 10, (1, 30), (8, 60), (9, 60));
    }

    private static void WriteRiskSignals(ExcelSheet sheet, List<DomainAssessment> domains) {
        const int header = 1;
        WriteHeader(sheet, header, "Domain", "Area", "Signal", "Reason", "Points", "Decisive", "Source", "Check");
        int row = header;
        foreach (DomainAssessment domain in domains) {
            foreach (RiskSignal signal in domain.RiskProfile!.Signals) {
                WriteRow(sheet, ++row, domain.Domain, Wording.FacetLabel(signal.Facet), signal.Id, signal.Reason, signal.Points,
                    signal.Decisive ? "Yes" : "No", signal.Source, signal.CheckKey ?? string.Empty);
                sheet.Cell(row, 1).SetFontFamily("Consolas");
                sheet.Cell(row, 5).SetColor(OfficeColor.Parse(signal.Points < 0 ? Good : signal.Points >= 20 || signal.Decisive ? High : Elevated));
            }
        }
        FinishSheet(sheet, header, row, 8, (1, 30), (3, 34), (4, 60));
        if (row == header) { WriteRow(sheet, header + 2, "No risk signals were observed."); }
    }

    private static void WriteRiskCoverage(ExcelSheet sheet, List<DomainAssessment> domains) {
        const int header = 1;
        WriteHeader(sheet, header, "Domain", "Area", "Counted", "Area coverage", "Evidence", "State", "Source", "Check", "Note", "Confidence gain");
        int row = header;
        foreach (DomainAssessment domain in domains) {
            DomainRiskProfile profile = domain.RiskProfile!;
            var gains = profile.Gaps.ToDictionary(static g => g.EvidenceId, static g => g.ConfidenceGain);
            foreach (ProfileFacet facet in profile.Facets) {
                foreach (EvidenceItem item in facet.Evidence) {
                    WriteRow(sheet, ++row, domain.Domain, Wording.FacetLabel(facet.Kind), facet.Counted ? "Yes" : "No", Wording.FacetCoverage(facet),
                        item.Label, Wording.EvidenceStateLabel(item.State), item.Source, item.CheckKey ?? string.Empty, item.Note ?? string.Empty,
                        gains.TryGetValue(item.Id, out double gain) ? gain.ToString("0.00", CultureInfo.InvariantCulture) : string.Empty);
                    sheet.Cell(row, 1).SetFontFamily("Consolas");
                    if (item.State is not (EvidenceState.Observed or EvidenceState.Clean)) { sheet.Cell(row, 6).SetColor(OfficeColor.Parse(Muted)); }
                }
            }
        }
        FinishSheet(sheet, header, row, 10, (1, 30), (5, 28), (9, 50));
    }

    private static string RiskColor(DomainRiskProfile profile) => !profile.Rated ? Muted : profile.RiskLevel switch {
        DomainRiskLevel.Critical or DomainRiskLevel.High => High,
        DomainRiskLevel.Medium => Elevated,
        DomainRiskLevel.Low => Muted,
        _ => profile.Confidence == EvidenceConfidence.High ? Good : Muted
    };
}
