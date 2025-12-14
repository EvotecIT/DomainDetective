using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Body rule: detects technologies by applying a regex to the HTML document body.
/// </summary>
public sealed class BodyRule
{
    /// <summary>Regular expression used to detect the technology in HTML content.</summary>
    [JsonPropertyName("regex")] public string Regex { get; set; } = null!;
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; } = null!;
}

