namespace DomainDetective
{
using System.Text.Json.Serialization;

/// <summary>
/// Represents an RDAP event entry.
/// </summary>
public sealed class RdapEvent
{
    /// <summary>Action type for the event.</summary>
    [JsonPropertyName("eventAction")]
    public RdapEventAction Action { get; set; }

    /// <summary>Date of the event.</summary>
    [JsonPropertyName("eventDate")]
    public string? Date { get; set; }
}
}
