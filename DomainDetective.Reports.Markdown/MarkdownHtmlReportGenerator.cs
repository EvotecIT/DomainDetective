using System.IO;
using OfficeIMO.Markdown;
using System.Threading.Tasks;
using DomainDetective.Reports;

namespace DomainDetective.Reports.Markdown;

/// <summary>Generates MarkdownHtml output through the shared assessment composition engine.</summary>
public sealed class MarkdownHtmlReportGenerator : IReportGenerator {
    /// <summary>Gets the output format.</summary>
    public ReportFormat Format => ReportFormat.MarkdownHtml;
    /// <summary>Determines whether this adapter handles the requested format.</summary>
    public bool CanGenerate(ReportOptions options) => options.Format == Format;
    /// <summary>Exports existing results with summaries, narratives, recommendations and supporting evidence.</summary>
    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options)
        => HealthCheckCompositionReport.GenerateAsync(healthCheck, options);

    /// <summary>Writes the assessment Markdown sidecar and its portable HTML rendering.</summary>
    public static void Generate(string path, DomainAssessmentReport report, AssessmentMarkdownOptions? options = null) {
        string markdownPath = Path.ChangeExtension(path, ".md");
        AssessmentMarkdownReport.Generate(markdownPath, report, options);
        using var document = MarkdownDocument.Parse(File.ReadAllText(markdownPath));
        document.SaveAsHtml(path, new MarkdownHtmlExportOptions {
            Kind = MarkdownHtmlKind.Document,
            Style = MarkdownHtmlStyle.GithubAuto,
            CssDelivery = MarkdownCssDelivery.Inline,
            IncludeAnchorLinks = false,
            ShowAnchorIcons = true,
            CopyHeadingLinkOnClick = true,
            BackToTopLinks = true,
            BackToTopMinLevel = 1,
            BackToTopText = "Back to top",
            ThemeToggle = true
        });
    }
}
