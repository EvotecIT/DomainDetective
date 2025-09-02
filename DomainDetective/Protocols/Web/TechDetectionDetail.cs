namespace DomainDetective;

/// <summary>
/// Describes a single technology detection with source, evidence and confidence.
/// </summary>
public sealed class TechDetectionDetail
{
    /// <summary>Technology name (e.g., WordPress, Cloudflare).</summary>
    public string Name { get; set; }
    /// <summary>Detection source (Header, Cookie, Meta, Path, Body, DomainSuffix, Heuristic).</summary>
    public string Source { get; set; }
    /// <summary>Short evidence snippet (e.g., header value or matched snippet).</summary>
    public string? Evidence { get; set; }
    /// <summary>Confidence score (0-100). Defaults to 100 for strong matches.</summary>
    public int Confidence { get; set; } = 100;
}

