using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Cookie rule: a 'Set-Cookie' value that contains the substring implies a 'tech'.
/// </summary>
public sealed class CookieRule
{
    /// <summary>Substring to look for in Set-Cookie values.</summary>
    [JsonPropertyName("contains")] public string Contains { get; set; }
    /// <summary>Technology label to record when matched.</summary>
    [JsonPropertyName("tech")] public string Tech { get; set; }
}

