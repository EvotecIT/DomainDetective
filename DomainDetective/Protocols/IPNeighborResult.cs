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
    /// <summary>True when the origin is valid per RPKI.</summary>
    public bool RPKIValid { get; init; }
    /// <summary>Total number of co-hosted domains observed.</summary>
    public int CoHostCount { get; set; }
    /// <summary>Simple categorization of co-hosting density (Low/Medium/High/Extreme).</summary>
    public string Category { get; set; } = string.Empty;
    /// <summary>Source type: "Apex" (A/AAAA) or "MX" (mail hosts).</summary>
    public string Type { get; set; } = "Apex";
}
