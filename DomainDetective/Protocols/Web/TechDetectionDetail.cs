namespace DomainDetective;

/// <summary>
/// Describes a single technology detection with source, evidence and confidence.
/// </summary>
public sealed class TechDetectionDetail
{
    /// <summary>Technology name (e.g., WordPress, Cloudflare).</summary>
    public string Name { get; set; }
    /// <summary>Typed detection source (e.g., Header, Cookie, ScriptSrc, Dns).</summary>
    public TechEvidenceKind SourceKind { get; set; }
    /// <summary>Short evidence snippet (e.g., header value, path, or matched regex).</summary>
    public string? Evidence { get; set; }
    /// <summary>Confidence score (0-100). Defaults to 100 for strong matches.</summary>
    public int Confidence { get; set; } = 100;
}

