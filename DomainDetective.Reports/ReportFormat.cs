namespace DomainDetective.Reports;

/// <summary>
/// Supported report output formats
/// </summary>
public enum ReportFormat {
    /// <summary>
    /// HTML report with interactive elements
    /// </summary>
    Html,
    
    /// <summary>
    /// Microsoft Word document
    /// </summary>
    Word,
    
    /// <summary>
    /// Microsoft Excel spreadsheet
    /// </summary>
    Excel,
    
    /// <summary>
    /// Portable Document Format
    /// </summary>
    Pdf,
    
    /// <summary>
    /// JSON data export
    /// </summary>
    Json,
    
    /// <summary>
    /// Markdown documentation
    /// </summary>
    Markdown,

    /// <summary>
    /// HTML generated from Markdown layout (also saves .md alongside .html)
    /// </summary>
    MarkdownHtml
}
