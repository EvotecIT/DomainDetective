namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// Represents an IP network object in RDAP.
/// </summary>
public sealed class RdapIpNetwork
{
    /// <summary>Starting IP address.</summary>
    [JsonPropertyName("startAddress")]
    public string? StartAddress { get; set; }

    /// <summary>Ending IP address.</summary>
    [JsonPropertyName("endAddress")]
    public string? EndAddress { get; set; }

    /// <summary>CIDR notation for the network.</summary>
    [JsonPropertyName("cidr")]
    public string? Cidr { get; set; }
}
}
