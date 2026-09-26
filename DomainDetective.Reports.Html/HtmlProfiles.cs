namespace DomainDetective.Reports.Html;

/// <summary>
/// Presentation profile for HTML reports. Assessment = scored assessment report (default for exports);
/// Document = legacy long-form; Dashboard = legacy compact KPIs/tables.
/// </summary>
public enum HtmlProfile
{
    /// <summary>Represents the document value.</summary>
    Document,
    /// <summary>Represents the dashboard value.</summary>
    Dashboard,
    /// <summary>Scored assessment report: summary, coverage across domains, and every check with evidence and guidance.</summary>
    Assessment
}

