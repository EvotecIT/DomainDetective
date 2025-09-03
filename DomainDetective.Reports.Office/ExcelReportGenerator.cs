using System;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using ClosedXML.Excel;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Generates a minimal Excel report using ClosedXML to unblock format support.
/// </summary>
public class ExcelReportGenerator : IReportGenerator {
    public ReportFormat Format => ReportFormat.Excel;

    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Excel;

    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        var outputPath = options.OutputPath ?? $"{domain}_security_report.xlsx";

        try {
            using var wb = new XLWorkbook();
            var ws = wb.Worksheets.Add("Summary");
            ws.Cell(1, 1).Value = "DomainDetective Security Report";
            ws.Cell(2, 1).Value = "Domain"; ws.Cell(2, 2).Value = domain;
            ws.Cell(3, 1).Value = "Generated"; ws.Cell(3, 2).Value = DateTime.Now;

            var assess = healthCheck.GetAllAssessments();
            int info = assess.Count(a => a.Severity == AssessmentSeverity.Info);
            int warn = assess.Count(a => a.Severity == AssessmentSeverity.Warning);
            int err = assess.Count(a => a.Severity == AssessmentSeverity.Error);

            ws.Cell(5, 1).Value = "Info"; ws.Cell(5, 2).Value = info;
            ws.Cell(6, 1).Value = "Warnings"; ws.Cell(6, 2).Value = warn;
            ws.Cell(7, 1).Value = "Errors"; ws.Cell(7, 2).Value = err;

            var recs = healthCheck.RecommendationViews ?? Array.Empty<RecommendationView>();
            var wr = wb.Worksheets.Add("Recommendations");
            wr.Cell(1, 1).Value = "Code";
            wr.Cell(1, 2).Value = "Title";
            int r = 2;
            foreach (var rec in recs.Take(100)) {
                wr.Cell(r, 1).Value = rec.Code;
                wr.Cell(r, 2).Value = rec.Advice?.Title ?? string.Empty;
                r++;
            }

            wb.SaveAs(outputPath);
            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = outputPath,
                Format = ReportFormat.Excel
            });
        } catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = outputPath,
                Format = ReportFormat.Excel,
                ErrorMessage = ex.Message
            });
        }
    }
}
