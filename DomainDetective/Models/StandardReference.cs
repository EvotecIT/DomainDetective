namespace DomainDetective;

/// <summary>Standard reference metadata (RFC or similar) used in signals.</summary>
public sealed class StandardReference {
    /// <summary>Human-friendly title.</summary>
    public string Title { get; init; }
    /// <summary>Reference identifier, e.g. RFC number.</summary>
    public string Reference { get; init; }
    /// <summary>Canonical URL to the specification.</summary>
    public string Url { get; init; }
}

