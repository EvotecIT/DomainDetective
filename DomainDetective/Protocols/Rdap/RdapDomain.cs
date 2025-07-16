namespace DomainDetective
{
using System.Collections.Generic;
using System.Text.Json.Serialization;

/// <summary>
/// Represents a domain object in RDAP.
/// </summary>
public sealed class RdapDomain
{
    /// <summary>LDH name of the domain.</summary>
    [JsonPropertyName("ldhName")]
    public string? LdhName { get; set; }

    /// <summary>Unicode representation.</summary>
    [JsonPropertyName("unicodeName")]
    public string? UnicodeName { get; set; }

    /// <summary>Domain handle.</summary>
    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    /// <summary>Status values reported for the domain.</summary>
    [JsonPropertyName("status")]
    public List<RdapStatus> Status { get; set; } = new();

    /// <summary>Event list.</summary>
    [JsonPropertyName("events")]
    public List<RdapEvent> Events { get; set; } = new();

    /// <summary>Associated entities.</summary>
    [JsonPropertyName("entities")]
    public List<RdapEntity> Entities { get; set; } = new();

    /// <summary>Authoritative nameservers.</summary>
    [JsonPropertyName("nameservers")]
    public List<RdapNameserver> Nameservers { get; set; } = new();
}
}
