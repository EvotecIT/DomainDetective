namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// Represents an RDAP nameserver object.
/// </summary>
public sealed class RdapNameserver
{
    /// <summary>LDH name of the nameserver.</summary>
    [JsonPropertyName("ldhName")]
    public string? LdhName { get; set; }
}
}
