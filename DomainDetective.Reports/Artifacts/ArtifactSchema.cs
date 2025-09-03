using System;
using System.Collections.Generic;

namespace DomainDetective.Reports.Artifacts;

/// <summary>
/// Describes the top-level metadata for an artifact emission.
/// </summary>
public sealed class ArtifactMetadata {
    public string SchemaVersion { get; set; } = "1.0";
    public string Subject { get; set; } = string.Empty;
    public string SubjectKind { get; set; } = "Domain"; // Domain | Url | Host | RRset
    public DateTimeOffset GeneratedAt { get; set; } = DateTimeOffset.UtcNow;
    public string GeneratorVersion { get; set; } = "unknown";
    public string RunId { get; set; } = Guid.NewGuid().ToString("n");
}

/// <summary>
/// Aggregated counters useful for quick comparisons without loading the full JSON payload.
/// </summary>
public sealed class ArtifactMetrics {
    public int AssessmentInfoCount { get; set; }
    public int AssessmentWarningCount { get; set; }
    public int AssessmentErrorCount { get; set; }
    public int RecommendationCount { get; set; }
    public int HostCount { get; set; }
    public int ResourceCount { get; set; }
    public long TransferBytes { get; set; }
    public double? TotalDurationSeconds { get; set; }
}

