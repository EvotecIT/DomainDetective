using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

/// <summary>
/// Options for report generation
/// </summary>
    public class ReportOptions {
    /// <summary>
    /// Report title
    /// </summary>
    public string Title { get; set; } = "Domain Security Report";
    
    /// <summary>
    /// Output file path
    /// </summary>
    public string OutputPath { get; set; } = string.Empty;
    
    /// <summary>
    /// Output format for the report
    /// </summary>
    public ReportFormat Format { get; set; } = ReportFormat.Html;
    
    /// <summary>
    /// Template to use (if applicable)
    /// </summary>
    public string TemplateName { get; set; } = "Default";
    
    /// <summary>
    /// Theme configuration
    /// </summary>
    public ReportTheme Theme { get; set; } = ReportTheme.Light;
    
    /// <summary>
    /// Include technical details
    /// </summary>
    public bool IncludeTechnicalDetails { get; set; } = true;
    
    /// <summary>
    /// Include recommendations
    /// </summary>
    public bool IncludeRecommendations { get; set; } = true;
    
    /// <summary>
    /// Include raw data export
    /// </summary>
    public bool IncludeRawData { get; set; } = false;

    /// <summary>
    /// Include Info-level assessments in Findings sections
    /// </summary>
    public bool ShowInfoFindings { get; set; } = true;
    
    /// <summary>
    /// Custom properties for specific generators
    /// </summary>
    public Dictionary<string, object> CustomProperties { get; set; } = new();
    
    /// <summary>
    /// Report generation timestamp
    /// </summary>
    public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
}
