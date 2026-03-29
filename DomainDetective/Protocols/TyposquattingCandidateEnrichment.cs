using DnsClientX;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Reusable enrichment settings for typosquatting candidates.
/// </summary>
public sealed class TyposquattingEnrichmentOptions
{
    /// <summary>Maximum number of candidates enriched per analysis run.</summary>
    public int MaxCandidates { get; set; }

    /// <summary>Maximum number of candidates enriched in parallel.</summary>
    public int MaxParallelism { get; set; } = 2;

    /// <summary>When true, only candidates with a DNS footprint are considered for enrichment.</summary>
    public bool RegisteredOnly { get; set; } = true;

    /// <summary>When true, WHOIS is queried for enriched candidates.</summary>
    public bool IncludeWhois { get; set; } = true;

    /// <summary>When true, HTTPS posture is collected for resolving candidates.</summary>
    public bool IncludeHttp { get; set; } = true;

    /// <summary>When true, static web discovery is collected for resolving candidates.</summary>
    public bool IncludeWebStaticScan { get; set; }

    /// <summary>When true, threat intelligence feeds are queried for enriched candidates.</summary>
    public bool IncludeThreatIntel { get; set; }

    /// <summary>When true, IP enrichment is collected for resolving candidates.</summary>
    public bool IncludeIpEnrichment { get; set; } = true;

    /// <summary>When true, HTTP enrichment captures the response body for downstream comparison.</summary>
    public bool CaptureHttpBody { get; set; }

    /// <summary>Custom request options used for HTTP checks.</summary>
    public HttpRequestOptions HttpRequestOptions { get; } = new();

    /// <summary>Optional Google Safe Browsing API key for threat enrichment.</summary>
    public string? GoogleSafeBrowsingApiKey { get; set; }

    /// <summary>Optional PhishTank API key for threat enrichment.</summary>
    public string? PhishTankApiKey { get; set; }

    /// <summary>Optional VirusTotal API key for threat enrichment.</summary>
    public string? VirusTotalApiKey { get; set; }

    /// <summary>Optional factory override for WHOIS enrichment.</summary>
    public Func<string, CancellationToken, Task<WhoisAnalysis?>>? WhoisOverride { get; set; }

    /// <summary>Optional factory override for HTTP enrichment.</summary>
    public Func<string, CancellationToken, Task<HttpAnalysis?>>? HttpOverride { get; set; }

    /// <summary>Optional factory override for static web enrichment.</summary>
    public Func<string, CancellationToken, Task<WebStaticScanAnalysis?>>? WebStaticScanOverride { get; set; }

    /// <summary>Optional factory override for threat enrichment.</summary>
    public Func<string, CancellationToken, Task<ThreatIntelAnalysis?>>? ThreatIntelOverride { get; set; }

    /// <summary>Optional factory override for IP enrichment.</summary>
    public Func<string, CancellationToken, Task<IpEnrichmentAnalysis?>>? IpEnrichmentOverride { get; set; }

    internal bool HasAnyEnabledChecks =>
        MaxCandidates > 0
        && (IncludeWhois || IncludeHttp || IncludeWebStaticScan || IncludeThreatIntel || IncludeIpEnrichment);
}

/// <summary>
/// Protocol-level enrichment bundle for a single typosquatting candidate.
/// </summary>
public sealed class TyposquattingCandidateEnrichment
{
    /// <summary>Candidate domain associated with this enrichment.</summary>
    public string Domain { get; init; } = string.Empty;

    /// <summary>Enrichment timestamp in UTC.</summary>
    public DateTimeOffset EnrichedAtUtc { get; internal set; }

    /// <summary>WHOIS analysis when requested.</summary>
    public WhoisAnalysis? Whois { get; internal set; }

    /// <summary>HTTP posture analysis when requested.</summary>
    public HttpAnalysis? Http { get; internal set; }

    /// <summary>Static website analysis when requested.</summary>
    public WebStaticScanAnalysis? WebStaticScan { get; internal set; }

    /// <summary>Threat intelligence analysis when requested.</summary>
    public ThreatIntelAnalysis? ThreatIntel { get; internal set; }

    /// <summary>IP enrichment analysis when requested.</summary>
    public IpEnrichmentAnalysis? IpEnrichment { get; internal set; }

    /// <summary>True when any enrichment artifact was collected.</summary>
    public bool HasAnyData =>
        Whois != null
        || Http != null
        || WebStaticScan != null
        || ThreatIntel != null
        || IpEnrichment != null;
}
