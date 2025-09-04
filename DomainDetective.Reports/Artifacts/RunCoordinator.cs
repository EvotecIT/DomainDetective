using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;

namespace DomainDetective.Reports.Artifacts;

/// <summary>
/// Coordinates a scan run: creates artifact directory, attaches progress sinks,
/// collects metrics and writes JSON artifacts.
/// </summary>
public sealed class RunCoordinator : IDisposable
{
    private readonly string _baseDirectory;
    private readonly string _subject;
    private readonly InternalLogger _logger;
    private readonly Stopwatch _sw = new Stopwatch();
    private readonly ProgressHub _hub;
    private readonly JsonlProgressSink _jsonl;

    public string RunDirectory { get; }
    public ArtifactMetadata Metadata { get; }

    private RunCoordinator(string baseDirectory, string subject, InternalLogger logger, string runDir, ArtifactMetadata metadata, ProgressHub hub, JsonlProgressSink jsonl)
    {
        _baseDirectory = baseDirectory;
        _subject = subject;
        _logger = logger;
        RunDirectory = runDir;
        Metadata = metadata;
        _hub = hub;
        _jsonl = jsonl;
    }

    public static RunCoordinator Begin(string subject, InternalLogger logger, string baseDirectory)
    {
        if (string.IsNullOrWhiteSpace(subject)) subject = "unknown";
        var meta = new ArtifactMetadata {
            Subject = subject,
            GeneratedAt = DateTimeOffset.UtcNow,
            GeneratorVersion = typeof(DomainHealthCheck).Assembly.GetName().Version?.ToString() ?? "unknown"
        };
        // best-effort subject kind heuristic
        if (Uri.TryCreate(subject, UriKind.Absolute, out _)) meta.SubjectKind = "Url";
        var safeSubject = FilePathHelper.MakeFileSafe(subject);
        var stamp = meta.GeneratedAt.ToUniversalTime().ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var runDir = Path.Combine(baseDirectory ?? ".", "artifacts", safeSubject, stamp);
        Directory.CreateDirectory(runDir);

        var hub = new ProgressHub(logger);
        var jsonl = new JsonlProgressSink(Path.Combine(runDir, "progress.jsonl"));
        hub.AddSink(jsonl);

        var coord = new RunCoordinator(baseDirectory, subject, logger, runDir, meta, hub, jsonl);
        coord._sw.Start();
        return coord;
    }

    public string End(DomainHealthCheck hc)
    {
        _sw.Stop();
        var metrics = new ArtifactMetrics {
            AssessmentInfoCount = CountBySeverity(hc, AssessmentSeverity.Info),
            AssessmentWarningCount = CountBySeverity(hc, AssessmentSeverity.Warning),
            AssessmentErrorCount = CountBySeverity(hc, AssessmentSeverity.Error),
            RecommendationCount = hc.RecommendationViews?.Count ?? 0,
            HostCount = hc.WebStaticScanAnalysis?.Hosts?.Count ?? 0,
            ResourceCount = hc.WebStaticScanAnalysis?.Requests?.Count ?? 0,
            TransferBytes = hc.WebStaticScanAnalysis?.Requests?.Where(r => r != null && r.ContentLength.HasValue).Sum(r => (long)r.ContentLength.Value) ?? 0,
            TotalDurationSeconds = _sw.Elapsed.TotalSeconds
        };

        var exporter = new ArtifactExporter(_baseDirectory);
        exporter.WriteAll(_subject, hc, Metadata, metrics);
        return RunDirectory;
    }

    public async System.Threading.Tasks.Task<(string RunDirectory, ReportResult Report)> EndAndExportAsync(
        DomainHealthCheck hc,
        ReportOptions options,
        string subject,
        bool openInBrowser = false)
    {
        var dir = End(hc);
        var dispatcher = new ReportDispatcher();
        var result = await dispatcher.GenerateAsync(hc, options, subject, openInBrowser).ConfigureAwait(false);
        return (dir, result);
    }


    private static int CountBySeverity(DomainHealthCheck hc, AssessmentSeverity severity)
    {
        int c = 0;
        foreach (var a in hc.GetAllAssessments()) if (a.Severity == severity) c++;
        return c;
    }

    public void Dispose()
    {
        try { _hub?.Dispose(); } catch { }
        try { _jsonl?.Dispose(); } catch { }
    }
}
