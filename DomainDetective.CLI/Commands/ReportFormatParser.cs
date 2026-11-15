using System;
using System.Collections.Generic;
using DomainDetective.Reports;

namespace DomainDetective.CLI.Commands;

/// <summary>Parses the shared report-format vocabulary for CLI report and desired-state exports.</summary>
internal static class ReportFormatParser {
    internal static IReadOnlyList<ReportFormat> Parse(IEnumerable<string>? entries) {
        var formats = new List<ReportFormat>();
        foreach (string entry in entries ?? Array.Empty<string>()) {
            foreach (string raw in (entry ?? string.Empty).Split(',')) {
                string token = raw.Trim().ToLowerInvariant();
                if (token.Length == 0) { continue; }
                ReportFormat format = token switch {
                    "html" => ReportFormat.Html,
                    "word" or "docx" => ReportFormat.Word,
                    "pdf" => ReportFormat.Pdf,
                    "excel" or "xlsx" => ReportFormat.Excel,
                    "markdown" or "md" => ReportFormat.Markdown,
                    "markdownhtml" or "mdhtml" => ReportFormat.MarkdownHtml,
                    "json" => ReportFormat.Json,
                    _ => throw new ArgumentException($"Unknown report format '{raw.Trim()}'. Use html, word, pdf, excel, markdown, markdownhtml or json.")
                };
                if (!formats.Contains(format)) { formats.Add(format); }
            }
        }
        return formats;
    }
}
