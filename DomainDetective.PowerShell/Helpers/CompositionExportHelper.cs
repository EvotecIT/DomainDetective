using System;
using System.Collections.Generic;
using DomainDetective.Reports;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Markdown;
using DomainDetective.Reports.Office;

namespace DomainDetective.PowerShell;

internal static class CompositionExportHelper
{
    internal static IReadOnlyList<string> WriteReports(
        IReadOnlyList<object> items,
        IReadOnlyList<ReportFormat> formats,
        string? explicitPath,
        string label,
        ReportScope scope,
        string defaultTitle,
        bool openInBrowser,
        Action<string?>? openReport,
        out bool hadUnsupportedFormats)
    {
        var generatedPaths = new List<string>();
        hadUnsupportedFormats = false;

        foreach (var format in formats)
        {
            var outputPath = ReportPathHelper.ResolveOutputPathForFormat(
                explicitPath,
                ExportDefaults.OutputDirectory,
                label,
                format,
                formats);

            if (format == ReportFormat.Word)
            {
                WordCompositionReport.Generate(
                    outputPath,
                    items,
                    scope,
                    showInfoFindings: true,
                    narrativePlacement: ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? defaultTitle : ExportDefaults.NarrativeTitle,
                    subjectOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject,
                    categoryOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCategory) ? null : ExportDefaults.NarrativeCategory,
                    keywordsOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeKeywords) ? null : ExportDefaults.NarrativeKeywords,
                    creatorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    companyName: string.IsNullOrWhiteSpace(ExportDefaults.CompanyName) ? null : ExportDefaults.CompanyName,
                    companyAddress: string.IsNullOrWhiteSpace(ExportDefaults.CompanyAddress) ? null : ExportDefaults.CompanyAddress,
                    companyYear: string.IsNullOrWhiteSpace(ExportDefaults.CompanyYear) ? null : ExportDefaults.CompanyYear,
                    logoPath: string.IsNullOrWhiteSpace(ExportDefaults.LogoPath) ? null : ExportDefaults.LogoPath,
                    headerText: string.IsNullOrWhiteSpace(ExportDefaults.HeaderText) ? null : ExportDefaults.HeaderText,
                    footerText: string.IsNullOrWhiteSpace(ExportDefaults.FooterText) ? null : ExportDefaults.FooterText,
                    watermarkText: string.IsNullOrWhiteSpace(ExportDefaults.WatermarkText) ? null : ExportDefaults.WatermarkText,
                    summaryColumnCap: ExportDefaults.SummaryColumnCap,
                    headerLogoSizePx: ExportDefaults.HeaderLogoSizePx,
                    footerLogoSizePx: ExportDefaults.FooterLogoSizePx);

                if (openInBrowser)
                {
                    openReport?.Invoke(outputPath);
                }

                generatedPaths.Add(outputPath);
                continue;
            }

            if (format == ReportFormat.Html)
            {
                HtmlCompositionReport.Generate(
                    outputPath,
                    items,
                    scope,
                    openInBrowser,
                    ExportDefaults.NarrativePlacement,
                    titleOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? defaultTitle : ExportDefaults.NarrativeTitle,
                    authorOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeCreator) ? null : ExportDefaults.NarrativeCreator,
                    descriptionOverride: string.IsNullOrWhiteSpace(ExportDefaults.NarrativeSubject) ? null : ExportDefaults.NarrativeSubject);

                generatedPaths.Add(outputPath);
                continue;
            }

            if (format == ReportFormat.Excel)
            {
                ExcelCompositionReport.Generate(outputPath, items, scope);
                if (openInBrowser)
                {
                    openReport?.Invoke(outputPath);
                }

                generatedPaths.Add(outputPath);
                continue;
            }

            if (format == ReportFormat.Markdown)
            {
                MarkdownCompositionReport.Generate(outputPath, items, scope);
                generatedPaths.Add(outputPath);
                continue;
            }

            if (format == ReportFormat.MarkdownHtml)
            {
                MarkdownCompositionReport.GenerateMarkdownHtml(outputPath, items, scope);
                if (openInBrowser)
                {
                    openReport?.Invoke(outputPath);
                }

                generatedPaths.Add(outputPath);
                continue;
            }

            hadUnsupportedFormats = true;
        }

        return generatedPaths;
    }
}
