namespace DomainDetective;

/// <summary>An SPF observation supplied by an aggregate reporter, without local host evaluation.</summary>
public sealed class DmarcSpfAuthenticationResult {
    /// <summary>Domain checked by the reporter.</summary>
    public string? Domain { get; set; }
    /// <summary>Identity scope checked by the reporter.</summary>
    public string? Scope { get; set; }
    /// <summary>Reported SPF evaluation result.</summary>
    public string? Result { get; set; }
    /// <summary>Additional diagnostic text from the reporter.</summary>
    public string? HumanResult { get; set; }
}
