namespace DomainDetective;

/// <summary>
/// Describes a single technology detection with source, evidence and confidence.
/// </summary>
public sealed class TechDetectionDetail
{
    /// <summary>Technology name (e.g., WordPress, Cloudflare).</summary>
    public string Name { get; set; } = null!;
    /// <summary>Typed detection source (e.g., Header, Cookie, ScriptSrc, Dns).</summary>
    public TechEvidenceKind SourceKind { get; set; }
    /// <summary>High-level technology category (e.g., CMS, WebServer, JSLibrary).</summary>
    public TechCategory Category { get; set; } = TechCategory.Other;
    /// <summary>Optional detected version string, when available.</summary>
    public string? Version { get; set; }
    /// <summary>Short evidence snippet (e.g., header value, path, or matched regex).</summary>
    public string? Evidence { get; set; }
    /// <summary>Confidence score (0-100). Defaults to 100 for strong matches.</summary>
    public int Confidence { get; set; } = 100;
}
