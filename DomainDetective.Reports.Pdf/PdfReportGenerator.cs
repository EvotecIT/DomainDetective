using System;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using QuestPDF.Fluent;
using QuestPDF.Infrastructure;

namespace DomainDetective.Reports.Pdf;

/// <summary>
/// Generates a minimal PDF report using QuestPDF to unblock format support.
/// </summary>
public class PdfReportGenerator : IReportGenerator {
    public ReportFormat Format => ReportFormat.Pdf;

    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Pdf;

    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        var outputPath = options.OutputPath ?? $"{domain}_security_report.pdf";

        try {
            var assess = healthCheck.GetAllAssessments();
            int info = assess.Count(a => a.Severity == AssessmentSeverity.Info);
            int warn = assess.Count(a => a.Severity == AssessmentSeverity.Warning);
            int err = assess.Count(a => a.Severity == AssessmentSeverity.Error);

            var recs = healthCheck.RecommendationViews ?? Array.Empty<RecommendationView>();

            Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Margin(40);
                    page.Header().Text("DomainDetective Security Report").Bold().FontSize(20);
                    page.Content().Column(col =>
                    {
                        col.Item().Text($"Domain: {domain}");
                        col.Item().Text($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        col.Item().Text($"Assessments: info={info}, warnings={warn}, errors={err}");
                        if (recs.Count > 0) {
                            col.Item().Text("Top Recommendations").Bold().FontSize(14);
                            foreach (var r in recs.Take(10))
                                col.Item().Text("• " + (r.Advice?.Title ?? r.Code));
                        }
                    });
                });
            }).GeneratePdf(outputPath);

            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = outputPath,
                Format = ReportFormat.Pdf
            });
        } catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = outputPath,
                Format = ReportFormat.Pdf,
                ErrorMessage = ex.Message
            });
        }
    }
}
