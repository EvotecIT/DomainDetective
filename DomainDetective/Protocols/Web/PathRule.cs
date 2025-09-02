using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Path rule: detects technologies by matching URL paths using a substring or regex.
/// </summary>
public sealed class PathRule
{
    /// <summary>Substring that should be present in the path. Optional when <see cref="Regex"/> is used.</summary>
    [JsonPropertyName("contains")] public string? Contains { get; set; }
    /// <summary>Regular expression used to match the path. Optional when <see cref="Contains"/> is used.</summary>
    [JsonPropertyName("regex")] public string? Regex { get; set; }
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; }
}

