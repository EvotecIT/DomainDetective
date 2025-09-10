using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using DomainDetective;
using DomainDetective.Reports;
using OfficeIMO.Markdown;

namespace DomainDetective.Reports.Markdown;

/// <summary>
/// Generates HTML by first producing Markdown that mirrors the Word layout, then saving an HTML rendition.
/// Also saves the .md alongside the .html.
/// </summary>
public sealed class HtmlAsMarkdownReportGenerator : IReportGenerator {
    public ReportFormat Format => ReportFormat.HtmlAsMarkdown;

    public bool CanGenerate(ReportOptions options) => options.Format == ReportFormat.HtmlAsMarkdown;

    public Task<ReportResult> GenerateAsync(DomainHealthCheck healthCheck, ReportOptions options) {
        var domain = options.CustomProperties?.ContainsKey("Domain") == true
            ? options.CustomProperties["Domain"]?.ToString() ?? "unknown"
            : "unknown";

        // Determine HTML output path (primary)
        var htmlPath = options.OutputPath;
        if (string.IsNullOrWhiteSpace(htmlPath)) {
            htmlPath = ReportPathHelper.GenerateDefaultPath(domain, ReportFormat.HtmlAsMarkdown, null);
        }
        if (!string.Equals(Path.GetExtension(htmlPath), ".html", StringComparison.OrdinalIgnoreCase)) {
            htmlPath = Path.ChangeExtension(htmlPath, ".html");
        }

        // Markdown path sits next to HTML
        var mdPath = Path.ChangeExtension(htmlPath, ".md");

        try {
            // Build Markdown once
            var md = MarkdownReportGenerator.BuildMarkdown(healthCheck, domain);

            // Save Markdown
            var mdText = md.ToMarkdown();
            File.WriteAllText(mdPath, mdText, Encoding.UTF8);

            // Save HTML rendition (GitHub-like style; inline CSS for portability)
            var htmlOptions = new HtmlOptions {
                Kind = HtmlKind.Document,
                Title = $"Domain Detective — {domain}",
                Style = HtmlStyle.GithubAuto,
                CssDelivery = CssDelivery.Inline,
                IncludeAnchorLinks = false,
                ShowAnchorIcons = true,
                AnchorIcon = "🔗",
                CopyHeadingLinkOnClick = true,
                BackToTopLinks = true,
                BackToTopMinLevel = 1,
                BackToTopText = "Back to top",
                ThemeToggle = true
            };
            md.SaveHtml(htmlPath, htmlOptions);

            var meta = new ReportMetadata {
                Domain = domain,
                TemplateName = "Markdown-Default",
            };
            meta.CustomProperties["MarkdownPath"] = mdPath;

            return Task.FromResult(new ReportResult {
                Success = true,
                FilePath = htmlPath,
                Format = ReportFormat.HtmlAsMarkdown,
                Metadata = meta
            });
        }
        catch (Exception ex) {
            return Task.FromResult(new ReportResult {
                Success = false,
                FilePath = htmlPath!,
                Format = ReportFormat.HtmlAsMarkdown,
                ErrorMessage = ex.Message
            });
        }
    }
}

