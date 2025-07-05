namespace DomainDetective;

/// <summary>
/// Entry describing a DNS server along with its country and location.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DnsComparisonEntry {
    /// <summary>IP address of the server.</summary>
    public string IPAddress { get; init; } = string.Empty;

    /// <summary>Country of the server.</summary>
    public string? Country { get; init; }

    /// <summary>Location of the server.</summary>
    public string? Location { get; init; }
}
