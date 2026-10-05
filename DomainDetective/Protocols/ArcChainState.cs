namespace DomainDetective;

/// <summary>
/// Describes the status of an ARC chain.
/// </summary>
public enum ArcChainState
{
    /// <summary>No ARC headers were present.</summary>
    Missing,
    /// <summary>ARC headers were found but the chain is invalid.</summary>
    Invalid,
    /// <summary>ARC sets and cv declarations pass structural checks; signatures have not been cryptographically verified.</summary>
    Valid
}
