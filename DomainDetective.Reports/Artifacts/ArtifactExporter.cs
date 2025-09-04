using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace DomainDetective.Reports.Artifacts;

/// <summary>
/// Writes structured artifacts (JSON/JSONL) for a given <see cref="DomainHealthCheck"/> run.
/// </summary>
public sealed class ArtifactExporter
{
    private readonly string _baseDirectory;
    private readonly JsonSerializerOptions _json;

    public ArtifactExporter(string baseDirectory, JsonSerializerOptions? json = null)
    {
        _baseDirectory = string.IsNullOrWhiteSpace(baseDirectory) ? "." : baseDirectory;
        _json = json ?? DomainDetective.Helpers.JsonOptions.Default;
    }

    /// <summary>
    /// Creates a new run directory under <c>artifacts/&lt;subject&gt;/&lt;timestamp&gt;</c> and writes core artifacts.
    /// Returns the full path to the created run directory.
    /// </summary>
    public string WriteAll(string subject, DomainHealthCheck hc, ArtifactMetadata meta, ArtifactMetrics metrics)
    {
        if (string.IsNullOrWhiteSpace(subject)) subject = "unknown";
        var safeSubject = MakeFileSafe(subject);
        var stamp = meta.GeneratedAt.ToUniversalTime().ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture);
        var runDir = Path.Combine(_baseDirectory, "artifacts", safeSubject, stamp);
        Directory.CreateDirectory(runDir);

        // 1) scan.json (top-level JSON with metadata + summary + assessments + recommendations + full HC)
        var scanEnvelope = new {
            metadata = meta,
            summary = hc.BuildSummary(),
            assessments = hc.GetAllAssessments(),
            recommendations = hc.RecommendationViews,
            health = hc
        };
        File.WriteAllText(Path.Combine(runDir, "scan.json"), JsonSerializer.Serialize(scanEnvelope, _json));

        // 2) metrics.json
        File.WriteAllText(Path.Combine(runDir, "metrics.json"), JsonSerializer.Serialize(metrics, _json));

        // 3) append index.jsonl (subject-level)
        try
        {
            var indexPath = Path.Combine(_baseDirectory, "artifacts", safeSubject, "index.jsonl");
            Directory.CreateDirectory(Path.GetDirectoryName(indexPath)!);
            var indexRecord = new {
                meta = meta,
                dir = runDir,
                counts = new { metrics.AssessmentInfoCount, metrics.AssessmentWarningCount, metrics.AssessmentErrorCount, metrics.RecommendationCount, metrics.HostCount, metrics.ResourceCount },
            };
            File.AppendAllText(indexPath, JsonSerializer.Serialize(indexRecord, _json) + Environment.NewLine);
        }
        catch { /* ignore index failures */ }

        return runDir;
    }

    private static string MakeFileSafe(string input)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input)
        {
            if (Array.IndexOf(invalid, ch) >= 0) { sb.Append('_'); } else { sb.Append(ch); }
        }
        return sb.ToString();
    }

}
