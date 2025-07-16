namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// Represents an autonomous system number object in RDAP.
/// </summary>
public sealed class RdapAutnum
{
    /// <summary>Autonomous system handle.</summary>
    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    /// <summary>Starting ASN.</summary>
    [JsonPropertyName("startAutnum")]
    public int? Start { get; set; }

    /// <summary>Ending ASN.</summary>
    [JsonPropertyName("endAutnum")]
    public int? End { get; set; }

    /// <summary>Autonomous system name.</summary>
    [JsonPropertyName("name")]
    public string? Name { get; set; }
}
}
