using System.Collections.Generic;

namespace DomainDetective.Narratives;

/// <summary>Represents narrative metadata and content sections used in reports.</summary>
public class NarrativeSections
{
    /// <summary>Gets or sets the primary title.</summary>
    public string Title { get; init; } = string.Empty;

    /// <summary>Gets or sets the secondary title or subtitle.</summary>
    public string Subtitle { get; init; } = string.Empty;

    /// <summary>Gets or sets the category of the narrative content.</summary>
    public string Category { get; init; } = string.Empty;

    /// <summary>Gets or sets comma-separated keywords associated with the narrative.</summary>
    public string Keywords { get; init; } = string.Empty;

    /// <summary>Gets or sets the creator or author of the narrative.</summary>
    public string Creator { get; init; } = string.Empty;

    /// <summary>Gets or sets the introductory text.</summary>
    public string Introduction { get; init; } = string.Empty;

    /// <summary>Gets or sets a description of why the topic matters.</summary>
    public string WhyItMatters { get; init; } = string.Empty;

    /// <summary>Gets the list of highlight bullet points.</summary>
    public List<string> Highlights { get; init; } = new();

    /// <summary>Gets the list of detailed bullet points.</summary>
    public List<string> Details { get; init; } = new();

    /// <summary>Gets the list of reference links.</summary>
    public List<string> References { get; init; } = new();

    /// <summary>Gets the list of positive notes.</summary>
    public List<string> Positives { get; init; } = new();

    /// <summary>Gets the list of remediation steps.</summary>
    public List<string> Remediations { get; init; } = new();
}
