namespace DomainDetective;

/// <summary>
/// Detailed comparison record for DNS propagation results.
/// </summary>
/// <para>Represents a single server and record set combination.</para>
public sealed class DnsComparisonDetail {
    /// <summary>The normalized record set.</summary>
    public string Records { get; init; } = string.Empty;

    /// <summary>IP address of the server.</summary>
    public string IPAddress { get; init; } = string.Empty;

    /// <summary>Country of the server.</summary>
    public string? Country { get; init; }

    /// <summary>Location of the server.</summary>
    public string? Location { get; init; }
}
