using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Domain rule: matches a registrable domain suffix to infer a technology.
/// </summary>
public sealed class DomainRule
{
    /// <summary>Domain suffix to match (e.g., cloudflare.com).</summary>
    [JsonPropertyName("suffix")] public string Suffix { get; set; }
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; }
}

