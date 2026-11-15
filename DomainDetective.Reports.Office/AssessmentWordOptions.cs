using OfficeIMO.Word;
using OfficeIMO.Word.Pdf;

namespace DomainDetective.Reports.Office;

/// <summary>Paper layout and conversion options for an assessment Word or PDF report.</summary>
public sealed class AssessmentWordOptions {
    /// <summary>Paper size; A4 is the default. Set Letter for a Letter paper workflow.</summary>
    public WordPageSize PageSize { get; set; } = WordPageSize.A4;

    /// <summary>Maximum number of prioritized actions on the summary; all results remain in the domain chapters and appendix.</summary>
    public int FixFirstCount { get; set; } = 10;

    /// <summary>Include informational findings alongside warnings and errors in check details.</summary>
    public bool ShowInfoFindings { get; set; }

    /// <summary>Whether to include a heading-based table of contents before the domain chapters.</summary>
    public bool IncludeTableOfContents { get; set; } = true;

    /// <summary>Optional first-party OfficeIMO PDF settings, including font resources.</summary>
    public WordPdfExportOptions? PdfOptions { get; set; }
}
