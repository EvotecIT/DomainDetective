using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
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
        out bool hadUnsupportedFormats, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var generatedPaths = new List<string>();
        hadUnsupportedFormats = false;
        var messages = items.Select(MessageEvidenceReport.TryCreate).Where(message => message != null).Select(message => message!).ToArray();
        if (messages.Length > 0 && messages.Length != items.Count) { throw new ArgumentException("Message evidence reports cannot be mixed with domain report items.", nameof(items)); }

        var settings = ExportDefaults.CreateReportRequest();
        settings.Scope = scope;
        settings.Formats = formats;
        AssessmentExportSettings.Validate(settings);

        DomainAssessmentReport? report = messages.Length == 0
            ? DomainAssessmentBuilder.Build(items, new DomainAssessmentOptions {
                Title = string.IsNullOrWhiteSpace(ExportDefaults.NarrativeTitle) ? defaultTitle : ExportDefaults.NarrativeTitle
            }) : null;

        formats = formats.Distinct().ToArray();
        var paths = formats.ToDictionary(format => format, format => ReportPathHelper.ResolveOutputPathForFormat(
            explicitPath, ExportDefaults.OutputDirectory, label, format, formats));
        Dictionary<ReportFormat, ReportResult>? paperResults = null;
        var failures = new List<Exception>();
        foreach (var format in formats)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var outputPath = paths[format];
            try {
                if (format is ReportFormat.Word or ReportFormat.Pdf) {
                    if (paperResults == null) {
                        var paperPaths = paths.Where(pair => pair.Key is ReportFormat.Word or ReportFormat.Pdf)
                            .ToDictionary(pair => pair.Key, pair => pair.Value);
                        paperResults = (messages.Length > 0
                            ? MessageHeaderOfficeReport.GenerateEvidenceReports(paperPaths, messages, cancellationToken)
                            : AssessmentWordReport.GenerateReports(paperPaths, report!, new AssessmentWordOptions { ShowInfoFindings = true }, cancellationToken))
                            .ToDictionary(result => result.Format);
                    }
                    ReportResult paper = paperResults[format];
                    if (!paper.Success) { throw new InvalidOperationException(paper.ErrorMessage); }
                    generatedPaths.Add(paper.FilePath);
                    if (openInBrowser) { openReport?.Invoke(paper.FilePath); }
                    continue;
                }

                if (messages.Length > 0) {
                    switch (format) {
                        case ReportFormat.Excel: MessageHeaderOfficeReport.GenerateEvidenceExcel(outputPath, messages); break;
                        case ReportFormat.Html: MessageHeaderHtmlReport.GenerateEvidence(outputPath, messages); break;
                        case ReportFormat.Markdown: MessageHeaderMarkdownReport.GenerateEvidence(outputPath, messages); break;
                        case ReportFormat.MarkdownHtml: MessageHeaderMarkdownReport.GenerateEvidence(outputPath, messages, html: true); break;
                        default: hadUnsupportedFormats = true; continue;
                    }
                    generatedPaths.Add(outputPath);
                    if (openInBrowser && format != ReportFormat.Markdown) { openReport?.Invoke(outputPath); }
                    continue;
                }

                switch (format) {
                    case ReportFormat.Excel:
                        AssessmentExcelReport.Generate(outputPath, report!, new AssessmentExcelOptions { ShowInfoFindings = true });
                        break;
                    case ReportFormat.Html:
                        AssessmentHtmlReport.Generate(outputPath, report!, new AssessmentHtmlOptions(), openInBrowser);
                        break;
                    case ReportFormat.Markdown:
                        AssessmentMarkdownReport.Generate(outputPath, report!, new AssessmentMarkdownOptions { ShowInfoFindings = true });
                        break;
                    case ReportFormat.MarkdownHtml:
                        MarkdownHtmlReportGenerator.Generate(outputPath, report!, new AssessmentMarkdownOptions { ShowInfoFindings = true });
                        break;
                    default:
                        hadUnsupportedFormats = true;
                        continue;
                }
                generatedPaths.Add(outputPath);
                if (openInBrowser && format != ReportFormat.Html && format != ReportFormat.Markdown) {
                    openReport?.Invoke(outputPath);
                }
            } catch (Exception ex) when (ex is not OperationCanceledException) {
                failures.Add(new InvalidOperationException($"{format} export to '{outputPath}' failed: {ex.Message}", ex));
            }
        }

        if (failures.Count > 0) { throw new AggregateException("Some report exports failed; other requested formats were still attempted.", failures); }
        return generatedPaths;
    }
}
