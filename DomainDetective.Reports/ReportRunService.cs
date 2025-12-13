using System;
using System.Threading.Tasks;
using DomainDetective.Reports.Artifacts;

namespace DomainDetective.Reports;

/// <summary>
/// High-level helpers for running checks with artifact capture and exporting reports.
/// </summary>
public static class ReportRunService
{
    /// <summary>
    /// Disposable scope that manages artifact capture and final export for a single report run.
    /// </summary>
    public sealed class ReportRunScope : IDisposable
    {
        private readonly RunCoordinator _coordinator;
        private readonly string _subject;
        /// <summary>Initializes the scope with a coordinator and subject label.</summary>
        public ReportRunScope(RunCoordinator coordinator, string subject)
        {
            _coordinator = coordinator;
            _subject = subject;
        }

        /// <summary>
        /// Exports the report and returns the run directory and result metadata.
        /// </summary>
        public async Task<(string RunDirectory, ReportResult Report)> ExportAsync(
            DomainHealthCheck hc,
            ReportFormat format,
            string? exportPath,
            string? defaultOutputDirectory,
            bool openInBrowser)
        {
            var outPath = ReportPathHelper.ResolveOutputPath(exportPath, defaultOutputDirectory, _subject, format);
            var options = new ReportOptions { Format = format, OutputPath = outPath };
            options.CustomProperties["Domain"] = _subject;
            var (dir, report) = await _coordinator.EndAndExportAsync(hc, options, _subject, openInBrowser).ConfigureAwait(false);
            return (dir, report);
        }

        /// <summary>Disposes the underlying coordinator.</summary>
        public void Dispose()
        {
            try { _coordinator?.Dispose(); } catch { }
        }
    }

    /// <summary>
    /// Creates a new report run scope for the specified subject and output locations.
    /// </summary>
    public static ReportRunScope Begin(InternalLogger logger, string subject, string? explicitExportPath, string? defaultOutputDirectory, string? artifactsDirectory = null)
    {
        var baseDir = !string.IsNullOrWhiteSpace(artifactsDirectory)
            ? artifactsDirectory!
            : FilePathHelper.ResolveBaseDirectory(explicitExportPath, defaultOutputDirectory);
        var coord = RunCoordinator.Begin(subject, logger, baseDir);
        return new ReportRunScope(coord, subject);
    }

    /// <summary>
    /// Runs the supplied work delegate inside an artifact run scope and exports the report.
    /// Captures progress/events for the whole execution and disposes resources automatically.
    /// </summary>
    public static async System.Threading.Tasks.Task<(string RunDirectory, ReportResult Report)> ExecuteWithArtifactsAsync(
        InternalLogger logger,
        string subject,
        DomainHealthCheck hc,
        System.Func<System.Threading.Tasks.Task> work,
        ReportFormat format,
        string? exportPath,
        string? defaultOutputDirectory,
        bool openInBrowser,
        string? artifactsDirectory = null)
    {
        using var scope = Begin(logger, subject, exportPath, defaultOutputDirectory, artifactsDirectory);
        await work().ConfigureAwait(false);
        return await scope.ExportAsync(hc, format, exportPath, defaultOutputDirectory, openInBrowser).ConfigureAwait(false);
    }

    /// <summary>
    /// Exports artifacts and a report after the checks have already run on the supplied health check.
    /// </summary>
    public static async System.Threading.Tasks.Task<(string RunDirectory, ReportResult Report)> ExportOnlyAsync(
        InternalLogger logger,
        string subject,
        DomainHealthCheck hc,
        ReportFormat format,
        string? exportPath,
        string? defaultOutputDirectory,
        bool openInBrowser,
        string? artifactsDirectory = null)
    {
        using var scope = Begin(logger, subject, exportPath, defaultOutputDirectory, artifactsDirectory);
        return await scope.ExportAsync(hc, format, exportPath, defaultOutputDirectory, openInBrowser).ConfigureAwait(false);
    }

}
