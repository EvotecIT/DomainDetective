namespace DomainDetective;

/// <summary>A DKIM observation supplied by an aggregate reporter, without local signature verification.</summary>
public sealed class DmarcDkimAuthenticationResult {
    /// <summary>Signing domain from the reported signature.</summary>
    public string? Domain { get; set; }
    /// <summary>Selector from the reported signature.</summary>
    public string? Selector { get; set; }
    /// <summary>Reported DKIM verification result.</summary>
    public string? Result { get; set; }
    /// <summary>Additional diagnostic text from the reporter.</summary>
    public string? HumanResult { get; set; }
}
