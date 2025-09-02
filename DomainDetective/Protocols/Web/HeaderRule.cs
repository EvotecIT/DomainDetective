using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Header rule: a header 'name' must contain the specified substring to infer a 'tech'.
/// </summary>
public sealed class HeaderRule
{
    /// <summary>Header name to inspect (e.g., X-Powered-By).</summary>
    [JsonPropertyName("name")] public string Name { get; set; }
    /// <summary>Substring to search for in the header value.</summary>
    [JsonPropertyName("contains")] public string Contains { get; set; }
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; }
}

