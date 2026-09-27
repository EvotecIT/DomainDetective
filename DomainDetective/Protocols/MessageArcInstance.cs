namespace DomainDetective;

/// <summary>One reported ARC instance. Structural completeness and cryptographic validity are separate.</summary>
public sealed class MessageArcInstance {
    /// <summary>ARC instance number.</summary>
    public int Instance { get; internal set; }
    /// <summary>Reported prior-chain validation token.</summary>
    public string? ChainValidation { get; internal set; }
    /// <summary>Seal signing domain.</summary>
    public string? SealerDomain { get; internal set; }
    /// <summary>ARC-Seal value, if present.</summary>
    public string? Seal { get; internal set; }
    /// <summary>ARC-Message-Signature value, if present.</summary>
    public string? MessageSignature { get; internal set; }
    /// <summary>ARC-Authentication-Results claims, if present. Local verification does not make a sealer trustworthy.</summary>
    public MessageAuthenticationEvidence? Authentication { get; internal set; }
}
