namespace DomainDetective
{
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// Represents an RDAP entity object.
/// </summary>
public sealed class RdapEntity
{
    /// <summary>Entity handle.</summary>
    [JsonPropertyName("handle")]
    public string? Handle { get; set; }

    /// <summary>Roles assigned to the entity.</summary>
    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = new();

    /// <summary>Raw vCard array.</summary>
    [JsonPropertyName("vcardArray")]
    public JsonElement? VcardArray { get; set; }
}
}
