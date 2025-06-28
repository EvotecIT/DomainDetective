using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Represents a set of domains hosted on a single IP.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class IPNeighborResult
{
    /// <summary>IP address shared by multiple domains.</summary>
    public string IpAddress { get; init; } = string.Empty;
    /// <summary>Domains associated with <see cref="IpAddress"/>.</summary>
    public List<string> Domains { get; set; } = new();
}
