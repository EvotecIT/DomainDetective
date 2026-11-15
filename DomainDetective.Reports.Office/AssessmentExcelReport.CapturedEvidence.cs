using System.Globalization;
using OfficeIMO.Excel;
using Wording = DomainDetective.Reports.AssessmentReportWording;

namespace DomainDetective.Reports.Office;

public static partial class AssessmentExcelReport {
    private static void WriteCapturedEvidence(ExcelSheet sheet, DomainAssessmentReport report) {
        WriteHeader(sheet, 1, "Domain", "Area", "Check", "Evidence", "Field", "Value", "Export note");
        int row = 1;
        foreach (DomainAssessment domain in report.Domains) {
            foreach (CheckAssessment check in domain.Checks) {
                foreach (CheckFact fact in check.Facts) {
                    WriteRow(sheet, ++row, domain.Domain, Wording.AreaLabel(check.Area), check.Title, "Facts", fact.Label, fact.Value);
                }
                foreach (CheckEvidence evidence in check.Evidence) {
                    if (evidence.Kind == CheckEvidenceKind.Code) {
                        WriteRow(sheet, ++row, domain.Domain, Wording.AreaLabel(check.Area), check.Title, evidence.Title, "Record", evidence.Text);
                    } else if (evidence.Kind == CheckEvidenceKind.List) {
                        for (int index = 0; index < evidence.Items.Count; index++) {
                            WriteRow(sheet, ++row, domain.Domain, Wording.AreaLabel(check.Area), check.Title, evidence.Title,
                                (index + 1).ToString(CultureInfo.InvariantCulture), evidence.Items[index]);
                        }
                    }
                    // Table omissions are recorded on their own evidence worksheet.
                    if (evidence.Kind != CheckEvidenceKind.Table && evidence.Omitted > 0) {
                        WriteRow(sheet, ++row, domain.Domain, Wording.AreaLabel(check.Area), check.Title, evidence.Title, null, null,
                            evidence.Omitted.ToString(CultureInfo.InvariantCulture) + " items omitted from the assessment model; not available in this export.");
                        sheet.Cell(row, 7).SetColor(OfficeColor.Parse(Muted));
                    }
                }
            }
        }
        FinishSheet(sheet, 1, row, 7, (1, 32), (6, 65), (7, 45));
    }
}
