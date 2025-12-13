using System;
using System.Linq;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using OfficeIMO.Word;

namespace DomainDetective.Reports.Office;

/// <summary>
/// Generates a minimal Word report using OfficeIMO to unblock format support.
/// </summary>
public class WordReportGenerator : IReportGenerator {
    public ReportFormat Format => ReportFormat.Word;

    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.Word;

    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        var outputPath = options.OutputPath ?? $"{domain}_security_report.docx";

        try {
            using var doc = WordDocument.Create(outputPath);
            doc.AddParagraph($"DomainDetective Security Report").SetBold().SetFontSize(24);
            doc.AddParagraph($"Domain: {domain}").SetItalic();
            doc.AddParagraph($"Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            doc.AddParagraph("");

            var summary = healthCheck.BuildSummary();
            doc.AddParagraph("Summary").SetBold().SetFontSize(18);
            doc.AddParagraph(summary?.ToString() ?? string.Empty);

            var assess = healthCheck.GetAllAssessments();
            int info = assess.Count(a => a.Severity == AssessmentSeverity.Info);
            int warn = assess.Count(a => a.Severity == AssessmentSeverity.Warning);
            int err = assess.Count(a => a.Severity == AssessmentSeverity.Error);
            doc.AddParagraph($"Assessments: info={info}, warnings={warn}, errors={err}");

            var topRecs = (healthCheck.RecommendationViews ?? Array.Empty<RecommendationView>()).Take(10).ToList();
            if (topRecs.Count > 0) {
                doc.AddParagraph("").AddParagraph("Top Recommendations").SetBold().SetFontSize(18);
                foreach (var r in topRecs) {
                    doc.AddParagraph($"- {r.Advice?.Title ?? r.Code}");
                }
            }

            doc.Save();
            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = outputPath,
                Format = ReportFormat.Word
            });
        } catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = outputPath,
                Format = ReportFormat.Word,
                ErrorMessage = ex.Message
            });
        }
    }
}
