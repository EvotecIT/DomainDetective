namespace DomainDetective.Reports.Office;

/// <summary>Settings for an assessment workbook.</summary>
public sealed class AssessmentExcelOptions {
    /// <summary>Maximum priority actions in the summary list. Defaults to ten; all checks remain in Checks.</summary>
    public int FixFirstCount { get; set; } = 10;

    /// <summary>Include informational findings, as in the HTML Explore dataset. Defaults to false.</summary>
    public bool ShowInfoFindings { get; set; }
}
