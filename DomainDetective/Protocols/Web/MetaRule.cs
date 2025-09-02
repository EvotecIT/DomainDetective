using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Meta rule: matches a meta tag by name and records a technology when its value contains a substring.
/// </summary>
public sealed class MetaRule
{
    /// <summary>Meta name attribute (e.g., generator).</summary>
    [JsonPropertyName("name")] public string Name { get; set; }
    /// <summary>Substring to search for within the meta content value.</summary>
    [JsonPropertyName("contains")] public string Contains { get; set; }
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; }
}

