namespace DomainDetective.Reports.Markdown;

/// <summary>Settings for an assessment in Markdown.</summary>
public sealed class AssessmentMarkdownOptions {
    /// <summary>Maximum priority actions. Defaults to ten; all checks remain in each domain's details.</summary>
    public int FixFirstCount { get; set; } = 10;

    /// <summary>Include informational findings alongside warnings and errors. Defaults to false, as in HTML.</summary>
    public bool ShowInfoFindings { get; set; }
}
