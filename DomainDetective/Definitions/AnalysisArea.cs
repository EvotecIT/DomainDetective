namespace DomainDetective;

/// <summary>
/// High-level analysis areas for grouping checks.
/// </summary>
public enum AnalysisArea
{
    /// <summary>Represents the general value.</summary>
    General = 0,
    /// <summary>Represents the dns value.</summary>
    DNS,
    /// <summary>Represents the mail value.</summary>
    Mail,
    /// <summary>Represents the web value.</summary>
    Web,
    /// <summary>Represents the security value.</summary>
    Security,
    /// <summary>Represents the identity value.</summary>
    Identity = 5
}
