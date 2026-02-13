namespace DomainDetective;

/// <summary>Syntax and normalization details for an email address.</summary>
public sealed class EmailAddressSyntaxDetails {
    /// <summary>Original or parsed address.</summary>
    public string? Address { get; set; }

    /// <summary>Local part (before '@').</summary>
    public string? Username { get; set; }

    /// <summary>Domain part (after '@').</summary>
    public string? Domain { get; set; }

    /// <summary>Normalized address (IDN domain normalized).</summary>
    public string? NormalizedEmail { get; set; }

    /// <summary>Indicates whether syntax is valid.</summary>
    public bool IsValidSyntax { get; set; }

    /// <summary>Optional suggestion for corrected address.</summary>
    public string? Suggestion { get; set; }

    /// <summary>Validation error message, if any.</summary>
    public string? Error { get; set; }
}
