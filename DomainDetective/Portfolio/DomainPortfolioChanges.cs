using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Classification of a portfolio snapshot change.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum DomainPortfolioChangeKind {
    /// <summary>A section or fact appears only in the current snapshot.</summary>
    Added,

    /// <summary>A section or fact appears only in the previous snapshot.</summary>
    Removed,

    /// <summary>A section or fact exists in both snapshots but has a different value.</summary>
    Changed
}

/// <summary>
/// Deterministic change row between two portfolio snapshots.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioChange {
    /// <summary>Stable change key.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Type of change.</summary>
    public DomainPortfolioChangeKind Kind { get; set; }

    /// <summary>Section key where the change occurred.</summary>
    public string SectionKey { get; set; } = string.Empty;

    /// <summary>Fact key when the change is fact-scoped.</summary>
    public string? FactKey { get; set; }

    /// <summary>Previous normalized value, if any.</summary>
    public string? PreviousValue { get; set; }

    /// <summary>Current normalized value, if any.</summary>
    public string? CurrentValue { get; set; }
}

/// <summary>
/// Change set produced by comparing two portfolio snapshots.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioChangeSet {
    /// <summary>Snapshot subject.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Previous snapshot capture time.</summary>
    public DateTimeOffset PreviousCapturedAtUtc { get; set; }

    /// <summary>Current snapshot capture time.</summary>
    public DateTimeOffset CurrentCapturedAtUtc { get; set; }

    /// <summary>Detected changes.</summary>
    public List<DomainPortfolioChange> Changes { get; set; } = new();
}
