using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace DomainDetective;

/// <summary>
/// Represents an optional set of technology detection rules loaded from JSON.
/// This extension mechanism is used only when a rules path is explicitly provided.
/// </summary>
public sealed class TechRuleSet
{
    /// <summary>Header substring matches. If the header name is X-Generator, the value is recorded as a tech.</summary>
    [JsonPropertyName("headers")] public List<HeaderRule>? Headers { get; set; }
    /// <summary>Cookie substring matches.</summary>
    [JsonPropertyName("cookies")] public List<CookieRule>? Cookies { get; set; }
    /// <summary>Meta tag matches by name and value substring (e.g., generator).</summary>
    [JsonPropertyName("meta")] public List<MetaRule>? Meta { get; set; }
    /// <summary>Path-level rules, either a substring 'contains' or a 'regex'.</summary>
    [JsonPropertyName("paths")] public List<PathRule>? Paths { get; set; }
    /// <summary>Registrable-domain-level rules matched by suffix.</summary>
    [JsonPropertyName("domains")] public List<DomainRule>? Domains { get; set; }
    /// <summary>Body HTML regex matches.</summary>
    [JsonPropertyName("body")] public List<BodyRule>? Body { get; set; }
}

