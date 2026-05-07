using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Score profile used by agent readiness analysis.
/// </summary>
public enum AgentReadinessScoreProfile {
    /// <summary>DomainDetective-owned balanced profile.</summary>
    DomainDetectiveDefault,
    /// <summary>Profile shaped around Cloudflare's public agent readiness checklist.</summary>
    CloudflareLike,
    /// <summary>Profile shaped around SEO and content-readiness scanners.</summary>
    SeoAgentReadiness
}

/// <summary>
/// Status of an individual agent readiness check.
/// </summary>
public enum AgentReadinessCheckStatus {
    /// <summary>The check passed.</summary>
    Pass,
    /// <summary>The check produced a warning.</summary>
    Warning,
    /// <summary>The check failed.</summary>
    Fail,
    /// <summary>The check is informational only.</summary>
    Info
}

/// <summary>
/// Options controlling agent readiness probing.
/// </summary>
public sealed class AgentReadinessOptions {
    /// <summary>HTTP timeout for each probe.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(20);
    /// <summary>Score profile used for category weights.</summary>
    public AgentReadinessScoreProfile ScoreProfile { get; set; } = AgentReadinessScoreProfile.DomainDetectiveDefault;
    /// <summary>When true, HTTP fallback is attempted after HTTPS origin probing fails.</summary>
    public bool AllowHttpFallback { get; set; } = true;
    /// <summary>Maximum response body characters retained per probe.</summary>
    public int MaxBodyCharacters { get; set; } = 256 * 1024;
    /// <summary>Maximum agent-facing endpoint probes, including endpoints discovered from Link headers and API catalogs.</summary>
    public int MaxEndpointProbes { get; set; } = 50;
    /// <summary>Optional user agent sent with probes.</summary>
    public string UserAgent { get; set; } = "Mozilla/5.0 (compatible; DomainDetective-AgentReadiness)";
}

/// <summary>
/// Single weighted readiness check.
/// </summary>
public sealed class AgentReadinessCheck {
    /// <summary>Stable check identifier.</summary>
    public string Id { get; set; } = string.Empty;
    /// <summary>Category containing this check.</summary>
    public string Category { get; set; } = string.Empty;
    /// <summary>Display name.</summary>
    public string Name { get; set; } = string.Empty;
    /// <summary>Current status.</summary>
    public AgentReadinessCheckStatus Status { get; set; }
    /// <summary>Score earned by this check.</summary>
    public double Score { get; set; }
    /// <summary>Maximum score for this check.</summary>
    public double MaxScore { get; set; }
    /// <summary>Human-readable evidence.</summary>
    public string Evidence { get; set; } = string.Empty;
    /// <summary>Associated assessment/recommendation code.</summary>
    public string Code { get; set; } = string.Empty;
}

/// <summary>
/// Weighted category score.
/// </summary>
public sealed class AgentReadinessCategoryScore {
    /// <summary>Category name.</summary>
    public string Category { get; set; } = string.Empty;
    /// <summary>Raw score in this category.</summary>
    public double Score { get; set; }
    /// <summary>Raw max score in this category.</summary>
    public double MaxScore { get; set; }
    /// <summary>Weighted contribution to the total percentage.</summary>
    public double WeightedScore { get; set; }
    /// <summary>Category weight in percent.</summary>
    public double Weight { get; set; }
    /// <summary>Passing check count.</summary>
    public int Passed { get; set; }
    /// <summary>Warning check count.</summary>
    public int Warnings { get; set; }
    /// <summary>Failed check count.</summary>
    public int Failed { get; set; }
}

/// <summary>
/// Parsed RFC 8288 Link header value.
/// </summary>
public sealed class AgentReadinessLinkRelation {
    /// <summary>Relation token.</summary>
    public string Relation { get; set; } = string.Empty;
    /// <summary>Resolved target URL.</summary>
    public string Target { get; set; } = string.Empty;
    /// <summary>Optional media type.</summary>
    public string? Type { get; set; }
    /// <summary>Source URL where the Link header was observed.</summary>
    public string SourceUrl { get; set; } = string.Empty;
    /// <summary>Raw link segment.</summary>
    public string Raw { get; set; } = string.Empty;
    /// <summary>Additional link parameters.</summary>
    public Dictionary<string, string> Parameters { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Agent-facing endpoint probe result.
/// </summary>
public sealed class AgentReadinessEndpointProbe {
    /// <summary>Logical endpoint kind.</summary>
    public string Kind { get; set; } = string.Empty;
    /// <summary>Probed URL.</summary>
    public string Url { get; set; } = string.Empty;
    /// <summary>HTTP status code when available.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Response content type.</summary>
    public string? ContentType { get; set; }
    /// <summary>Whether JSON parsed successfully.</summary>
    public bool ValidJson { get; set; }
    /// <summary>Whether the endpoint matches the expected minimal shape for its kind.</summary>
    public bool ShapeValid { get; set; }
    /// <summary>Detected endpoint shape name.</summary>
    public string? Shape { get; set; }
    /// <summary>Whether the endpoint is considered present.</summary>
    public bool Present { get; set; }
    /// <summary>Discovery source such as well-known or Link header.</summary>
    public string DiscoverySource { get; set; } = string.Empty;
    /// <summary>Probe error when available.</summary>
    public string? Error { get; set; }
}

/// <summary>
/// Parsed Content-Signal policy.
/// </summary>
public sealed class ContentSignalPolicy {
    /// <summary>Search permission value.</summary>
    public string? Search { get; set; }
    /// <summary>AI input permission value.</summary>
    public string? AiInput { get; set; }
    /// <summary>AI training permission value.</summary>
    public string? AiTrain { get; set; }
    /// <summary>Raw header or directive value.</summary>
    public string RawValue { get; set; } = string.Empty;
    /// <summary>Source where the policy was found.</summary>
    public string Source { get; set; } = string.Empty;
}

/// <summary>
/// Markdown negotiation and alternate discovery result.
/// </summary>
public sealed class MarkdownNegotiationResult {
    /// <summary>Requested URL.</summary>
    public string RequestedUrl { get; set; } = string.Empty;
    /// <summary>Status code from the markdown request.</summary>
    public int? StatusCode { get; set; }
    /// <summary>Content type returned by the markdown request.</summary>
    public string? ContentType { get; set; }
    /// <summary>Whether the response varies by Accept header.</summary>
    public bool VaryAccept { get; set; }
    /// <summary>True when direct negotiation returned markdown.</summary>
    public bool DirectMarkdown { get; set; }
    /// <summary>Discovered alternate markdown URL.</summary>
    public string? AlternateMarkdownUrl { get; set; }
}
