using System;

namespace DomainDetective.Reports.Html;

/// <summary>
/// Presentation profile for HTML reports. Every profile renders the scored assessment report; Document and Dashboard
/// remain only so existing scripts keep working.
/// </summary>
public enum HtmlProfile
{
    /// <summary>Retired long-form layout; renders the assessment report.</summary>
    [Obsolete("The Document layout was retired; HTML reports use the assessment report.")]
    Document,
    /// <summary>Retired compact layout; renders the assessment report.</summary>
    [Obsolete("The Dashboard layout was retired; HTML reports use the assessment report.")]
    Dashboard,
    /// <summary>Scored assessment report: summary, coverage across domains, and every check with evidence and guidance.</summary>
    Assessment
}
