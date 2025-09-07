using System;

namespace DomainDetective.Reports;

/// <summary>
/// Controls the detail level of section writers.
/// </summary>
public enum ReportScope
{
    Minimal,
    Normal,
    Detailed
}

/// <summary>
/// Controls where narrative text (Introduction/Why this matters/overview) is rendered.
/// </summary>
public enum NarrativePlacement
{
    /// <summary>Use Background section when multiple domains are present; otherwise include narratives inside per-domain sections.</summary>
    Auto,
    /// <summary>Render a single Background section with narratives; omit narratives from per-domain writers.</summary>
    Global,
    /// <summary>Each per-domain section includes its narrative sub-sections.</summary>
    PerDomain,
    /// <summary>Do not render narrative sub-sections.</summary>
    None
}
