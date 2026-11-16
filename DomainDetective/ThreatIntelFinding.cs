namespace DomainDetective;

/// <summary>
/// Represents the result from a single threat intelligence source.
/// </summary>
public readonly struct ThreatIntelFinding
{
    /// <summary>Origin of the finding.</summary>
    public ThreatIntelSource Source { get; init; }

    /// <summary>Indicates whether the source reported a listing.</summary>
    public bool IsListed { get; init; }

    /// <summary>
    /// Whether the source was asked and what it said. <see cref="IsListed"/> is false both for a clean answer and for a
    /// source that was never queried; this tells them apart.
    /// </summary>
    public ThreatIntelQueryState State { get; init; }

    /// <inheritdoc />
    public override string ToString()
    {
        return State switch
        {
            ThreatIntelQueryState.NotQueried => $"{Source}: Not queried",
            ThreatIntelQueryState.Failed => $"{Source}: Query failed",
            _ => $"{Source}: {(IsListed ? "Listed" : "Not listed")}"
        };
    }
}

/// <summary>Outcome of one threat intelligence source query.</summary>
public enum ThreatIntelQueryState
{
    /// <summary>The source was not queried (no API key, or disabled).</summary>
    NotQueried,
    /// <summary>The source answered and the domain is not listed.</summary>
    Clean,
    /// <summary>The source answered and lists the domain.</summary>
    Listed,
    /// <summary>The query failed.</summary>
    Failed
}
