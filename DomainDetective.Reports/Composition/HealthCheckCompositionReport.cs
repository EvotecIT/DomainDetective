using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective.Reports;

/// <summary>Routes general document exports through the same composition engine as mixed-view reports.</summary>
public static class HealthCheckCompositionReport {
    /// <summary>Generates a report from existing analysis results, without rerunning classification or DNS checks.</summary>
    public static async Task<ReportResult> GenerateAsync(DomainHealthCheck health, ReportOptions options) {
        if (health == null) { throw new ArgumentNullException(nameof(health)); }
        if (options == null) { throw new ArgumentNullException(nameof(options)); }
        var subject = options.CustomProperties?.TryGetValue("Domain", out var domain) == true ? domain?.ToString() ?? "unknown" : "unknown";
        var path = string.IsNullOrWhiteSpace(options.OutputPath)
            ? ReportPathHelper.GenerateDefaultPath(subject, options.Format, null) : options.OutputPath;
        var errors = new List<string>();
        var items = HealthCheckReportItems.BuildItems(health, subject, null, true, errors)
            .Where(item => CompositionUtilities.ExtractSubjects(new[] { item }).Count > 0).ToArray();
        if (errors.Count > 0 || items.Length == 0) {
            return new ReportResult {
                Success = false, FilePath = path, Format = options.Format,
                ErrorMessage = errors.Count > 0 ? "Report view conversion failed: " + string.Join("; ", errors) : "No completed, supported analysis results are available to report."
            };
        }
        var result = await CompositionExportService.ExportAsync(new CompositionExportRequest {
            Items = items, Formats = new[] { options.Format }, ExportPath = path,
            Scope = options.IncludeTechnicalDetails ? ReportScope.Detailed : ReportScope.Minimal,
            ShowInfoFindings = options.ShowInfoFindings, Title = options.Title,
            Subject = subject, AutoCollectTtl = false
        }).ConfigureAwait(false);
        var report = result.Reports.Single();
        report.Metadata = new ReportMetadata { Domain = subject, TemplateName = "Composition" };
        if (options.Format == ReportFormat.MarkdownHtml) { report.Metadata.CustomProperties["MarkdownPath"] = System.IO.Path.ChangeExtension(report.FilePath, ".md"); }
        return report;
    }
}
