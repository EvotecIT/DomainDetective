using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

/// <summary>
/// Describes which sections to include and how to render them.
/// </summary>
/// <summary>
/// Describes which sections to include and how to render them.
/// </summary>
public sealed class CompositionPlan
{
    /// <summary>
    /// Sections to include (SPF, DKIM, DMARC, DNSBL, ...).
    /// </summary>
    public IReadOnlyList<DomainDetective.HealthCheckType> Sections { get; set; } = Array.Empty<DomainDetective.HealthCheckType>();

    /// <summary>
    /// Detail level for all sections.
    /// </summary>
    public ReportScope Scope { get; set; } = ReportScope.Normal;

    /// <summary>
    /// Whether to include an executive summary across domains.
    /// </summary>
    public bool IncludeExecutiveSummary { get; set; } = true;
}
