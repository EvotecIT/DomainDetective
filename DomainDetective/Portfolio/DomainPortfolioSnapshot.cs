using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Storage-free aggregate view of domain evidence suitable for persistence by higher-level products.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioSnapshot {
    /// <summary>Snapshot contract version for persistence and migration.</summary>
    public int SchemaVersion { get; set; } = 1;

    /// <summary>Domain or host that was assessed.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the snapshot was synthesized.</summary>
    public DateTimeOffset CapturedAtUtc { get; set; }

    /// <summary>Version of the DomainDetective assembly that synthesized the snapshot.</summary>
    public string EvaluatorVersion { get; set; } = string.Empty;

    /// <summary>Evidence sections keyed by health check or product-neutral domain area.</summary>
    public List<DomainPortfolioSection> Sections { get; set; } = new();

    /// <summary>Typed high-value summaries for storage and dashboard projections.</summary>
    public DomainPortfolioSummaries Summaries { get; set; } = new();

    /// <summary>Flattened assessments from all snapshot sections.</summary>
    public List<Assessment> Assessments { get; set; } = new();
}

/// <summary>
/// A check-oriented evidence section inside a <see cref="DomainPortfolioSnapshot"/>.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioSection {
    /// <summary>Stable section key, normally a <see cref="HealthCheckType"/> name.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Human-readable section name.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>High-level area such as DNS, Mail, Web, Security, Identity, or General.</summary>
    public string Area { get; set; } = string.Empty;

    /// <summary>Computed section status based on collected assessments.</summary>
    public string Status { get; set; } = "Unknown";

    /// <summary>Number of warning assessments in this section.</summary>
    public int WarningCount { get; set; }

    /// <summary>Number of error assessments in this section.</summary>
    public int ErrorCount { get; set; }

    /// <summary>Storage-friendly scalar facts extracted from the analysis result.</summary>
    public List<DomainPortfolioFact> Facts { get; set; } = new();

    /// <summary>Assessments that belong to this section.</summary>
    public List<Assessment> Assessments { get; set; } = new();
}

/// <summary>
/// A stable scalar value captured from an analysis result.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioFact {
    /// <summary>Stable fact key within the section.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Human-readable fact label.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Normalized string value. Collections are joined deterministically.</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Value kind used by consumers that want typed storage columns.</summary>
    public DomainPortfolioFactKind Kind { get; set; } = DomainPortfolioFactKind.String;
}

/// <summary>
/// Storage-oriented type hint for a portfolio snapshot fact.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum DomainPortfolioFactKind {
    /// <summary>Text value.</summary>
    String,

    /// <summary>Boolean value.</summary>
    Boolean,

    /// <summary>Numeric value.</summary>
    Number,

    /// <summary>Date or date-time value.</summary>
    DateTime,

    /// <summary>Time span value.</summary>
    Duration,

    /// <summary>Deterministically joined scalar collection.</summary>
    Collection
}
