using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;
using System.Text.Json;
using System.IO;

namespace DomainDetective;

/// <summary>
/// Performs a static (non-browser) scan of a web page to collect resource metadata and host TLS summaries.
/// </summary>
/// <para>Focuses on data gathering and reuse of existing HttpAnalysis and TLS helpers.</para>
public partial class WebStaticScanAnalysis : IHasAssessments
{
    public string? Subject { get; set; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public int MaxResources { get; set; } = 300;
    public int Concurrency { get; set; } = 8;
    /// <summary>Maximum parallel header fetches for discovered resources; 0 defers to Concurrency.</summary>
    public int DiscoveryConcurrency { get; set; } = 0;
    /// <summary>Maximum parallel CSS fetches/processing; 0 defers to Concurrency.</summary>
    public int CssConcurrency { get; set; } = 0;
    /// <summary>Maximum parallel TLS probes; 0 defers to Concurrency.</summary>
    public int TlsConcurrency { get; set; } = 0;
    /// <summary>Maximum parallel DNS/RDAP enrichments; 0 defers to Concurrency.</summary>
    public int DnsConcurrency { get; set; } = 0;
    public bool RespectRobots { get; set; } = false;
    public bool EnableThreatIntel { get; set; } = false;
    /// <summary>When true, skip third-party resources; only first-party (same registrable domain) are fetched.</summary>
    public bool SkipThirdParty { get; set; } = false;
    /// <summary>Maximum number of resources to fetch per host. Applies to initial and CSS-discovered resources.</summary>
    public int MaxResourcesPerHost { get; set; } = 50;

    /// <summary>DNS configuration used for host/IP enrichment when needed.</summary>
    public DnsConfiguration DnsConfiguration { get; set; } = new DnsConfiguration();

    /// <summary>Optional function to obtain the registrable domain (PSL).</summary>
    public Func<string, string>? GetRegistrableDomain { get; set; }
    /// <summary>Optional path to a JSON rules file defining additional tech detection patterns.</summary>
    public string? TechRulesPath { get; set; }
    private TechRuleSet? _techRules;
    private bool _techRulesTried;
    private readonly object _sync = new();

    public class StaticRequest
    {
        public string Url { get; set; }
        public string Host { get; set; }
        public string Method { get; set; }
        public int StatusCode { get; set; }
        public string? ContentType { get; set; }
        public long? ContentLength { get; set; }
        public string? FinalUrl { get; set; }
    }

    public class StaticHost
    {
        public string Host { get; set; }
        public string? RegistrableDomain { get; set; }
        public List<string> IpAddresses { get; } = new();
        public string? Cidr { get; set; }
        public int? Asn { get; set; }
        public string? AsName { get; set; }
        public string? Country { get; set; }
        public TlsProbe.Result? Tls { get; set; }
        public int RequestCount { get; set; }
        public long Bytes { get; set; }
        public bool FirstParty { get; set; }
        public Dictionary<string, long> BytesByType { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Whether any AAAA (IPv6) address was resolved for this host.</summary>
        public bool HasIPv6 { get; set; }
        /// <summary>Minimum TTL seen for A answers (seconds).</summary>
        public int? ATtlMin { get; set; }
        /// <summary>Maximum TTL seen for A answers (seconds).</summary>
        public int? ATtlMax { get; set; }
        /// <summary>Minimum TTL seen for AAAA answers (seconds).</summary>
        public int? AAAATtlMin { get; set; }
        /// <summary>Maximum TTL seen for AAAA answers (seconds).</summary>
        public int? AAAATtlMax { get; set; }
        /// <summary>Edge/CDN provider inferred from headers (e.g., Cloudflare, CloudFront, Fastly, Azure Front Door).</summary>
        public string? EdgeProvider { get; set; }
        /// <summary>Edge Point-of-Presence code when available (e.g., CF-RAY suffix or X-Amz-Cf-Pop).</summary>
        public string? EdgePop { get; set; }
        /// <summary>Edge cache status when available (e.g., HIT/MISS).</summary>
        public string? EdgeCacheStatus { get; set; }
        /// <summary>Human-friendly PoP city when resolvable (best-effort, offline map).</summary>
        public string? EdgePopCity { get; set; }
        /// <summary>Human-friendly PoP country when resolvable (best-effort, offline map).</summary>
        public string? EdgePopCountry { get; set; }
        /// <summary>Region for the PoP, e.g., Europe, North America (best-effort).</summary>
        public string? EdgePopRegion { get; set; }
    }

    public HttpAnalysis? MainHttpAnalysis { get; private set; }
    /// <summary>Registrable domain derived from the scanned URL host.</summary>
    public string? PrimaryRegistrableDomain { get; private set; }
    /// <summary>Extracted HTML page title when available.</summary>
    public string? PageTitle { get; private set; }
    public List<StaticRequest> Requests { get; } = new();
    public Dictionary<string, StaticHost> Hosts { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, long> BytesByType { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Technologies detected via compiled rules and optional JSON extensions.</summary>
    public HashSet<string> TechDetections { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Tracker domains used during the scan (suffix-based, curated list).</summary>
    public HashSet<string> TrackersUsed { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Total number of Set-Cookie headers observed across resource requests.</summary>
    public int CookiesSet { get => _cookiesSet; private set => _cookiesSet = value; }
    private int _cookiesSet;
    public List<Assessment> Assessments { get; } = new();
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);
    /// <summary>Detailed records for each technology detection.</summary>
    public System.Collections.Generic.List<TechDetectionDetail> TechDetails { get; } = new();
    /// <summary>Aggregated cookie attribute posture for first-party cookies observed.</summary>
    public CookieAttributeSummary CookieSummary { get; } = new CookieAttributeSummary();
    /// <summary>Aggregated CORS headers posture for first-party responses.</summary>
    public CorsSummary Cors { get; } = new CorsSummary();
    /// <summary>Aggregated Server-Timing metrics observed on first-party responses.</summary>
    public ServerTimingSummary ServerTiming { get; } = new ServerTimingSummary();
    /// <summary>Link hints discovered in the main document (preconnect/dns-prefetch/preload/prefetch).</summary>
    public System.Collections.Generic.List<LinkHint> LinkHints { get; } = new System.Collections.Generic.List<LinkHint>();
    /// <summary>Sitemaps referenced by robots.txt for the primary host (no crawling).</summary>
    public System.Collections.Generic.List<string> RobotsSitemaps { get; } = new System.Collections.Generic.List<string>();
    /// <summary>Counts of structured data schema types found in application/ld+json blocks.</summary>
    public System.Collections.Generic.Dictionary<string,int> StructuredDataTypes { get; } = new System.Collections.Generic.Dictionary<string,int>(System.StringComparer.OrdinalIgnoreCase);

    public sealed class CookieAttributeSummary
    {
        public int TotalFirstParty { get; internal set; }
        public int Secure { get; internal set; }
        public int HttpOnly { get; internal set; }
        public int SameSiteLax { get; internal set; }
        public int SameSiteStrict { get; internal set; }
        public int SameSiteNone { get; internal set; }
        public int SameSiteMissing { get; internal set; }
        public int MaxAgePresent { get; internal set; }
        public int DomainPresent { get; internal set; }
        internal void Clear()
        {
            TotalFirstParty = Secure = HttpOnly = SameSiteLax = SameSiteStrict = SameSiteNone = SameSiteMissing = MaxAgePresent = DomainPresent = 0;
        }
    }

    public sealed class CorsSummary
    {
        public int FirstPartyResponses { get; internal set; }
        public int WildcardOriginCount { get; internal set; }
        public int CredentialsCount { get; internal set; }
        public System.Collections.Generic.HashSet<string> Origins { get; } = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        public System.Collections.Generic.HashSet<string> Methods { get; } = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        public System.Collections.Generic.HashSet<string> Headers { get; } = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear()
        {
            FirstPartyResponses = 0; WildcardOriginCount = 0; CredentialsCount = 0; Origins.Clear(); Methods.Clear(); Headers.Clear();
        }
    }

    public sealed class ServerTimingSummary
    {
        public int FirstPartyResponses { get; internal set; }
        public System.Collections.Generic.HashSet<string> Metrics { get; } = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        internal void Clear() { FirstPartyResponses = 0; Metrics.Clear(); }
    }

    public sealed class LinkHint
    {
        public string Rel { get; set; }
        public string Href { get; set; }
        public string? Host { get; set; }
        public bool FirstParty { get; set; }
    }

    // Regex helpers moved to Regexes partial

    public async Task Analyze(string url, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        Subject = url;
        Requests.Clear();
        Hosts.Clear();
        _cookiesSet = 0;
        CookieSummary.Clear();
        Cors.Clear();
        ServerTiming.Clear();
        LinkHints.Clear();
        RobotsSitemaps.Clear();

        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "WEBSTATIC", target: url);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true }) { Timeout = Timeout };
        Uri baseUri = new Uri(url);
        PrimaryRegistrableDomain = GetRegistrableDomain?.Invoke(baseUri.Host) ?? baseUri.Host;

        // Progress: start
        logger?.WriteVerbose("[WEB] Static scan start: {0}", url);
        logger?.WriteProgress("WEBSTATIC", "Fetch main document", 5.0, 0, 6);
        // 1) Reuse HttpAnalysis for main document posture
        MainHttpAnalysis = new HttpAnalysis();
        await MainHttpAnalysis.AnalyzeUrl(url, checkHsts: true, logger: logger, collectHeaders: true, captureBody: true, cancellationToken);
        string? body = MainHttpAnalysis.Body;
        try { logger?.WriteVerbose("[WEB] Main document: {0} ({1} bytes)", MainHttpAnalysis.StatusCode, MainHttpAnalysis.BodyLength ?? (body?.Length ?? 0)); } catch { }
        // Title extraction
        try {
            if (!string.IsNullOrWhiteSpace(body))
            {
                var m = System.Text.RegularExpressions.Regex.Match(body, "<title>(.*?)</title>", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.Singleline);
                if (m.Success) PageTitle = System.Net.WebUtility.HtmlDecode((m.Groups[1].Value ?? string.Empty).Trim());
            }
        } catch { }
        // Inspect base headers for technology hints (X-Powered-By, Set-Cookie, X-Generator)
        try {
            using var headReq = new HttpRequestMessage(HttpMethod.Head, baseUri);
            using var headResp = await http.SendAsync(headReq, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            // X-Powered-By
            if (headResp.Headers.TryGetValues("X-Powered-By", out var xp))
            {
                foreach (var v in xp)
                {
                    var low = (v ?? string.Empty).ToLowerInvariant();
                    if (low.Contains("php")) TechDetections.Add("PHP");
                    if (low.Contains("asp.net core")) TechDetections.Add("ASP.NET Core");
                    else if (low.Contains("asp.net")) TechDetections.Add("ASP.NET");
                    if (low.Contains("express")) TechDetections.Add("Express");
                    if (low.Contains("laravel")) TechDetections.Add("Laravel");
                    if (low.Contains("django")) TechDetections.Add("Django");
                }
            }
            // X-Generator
            if (headResp.Headers.TryGetValues("X-Generator", out var xg))
            {
                foreach (var v in xg) if (!string.IsNullOrWhiteSpace(v)) TechDetections.Add(v.Split(' ')[0]);
            }
            // Server header will be processed by signature catalog (Header rules)
            // Cookies → framework hints + posture aggregation for first-party
            if (headResp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var c in cookies)
                {
                    var low = (c ?? string.Empty).ToLowerInvariant();
                    if (low.Contains("phpsessid")) TechDetections.Add("PHP");
                    if (low.Contains("laravel_session")) TechDetections.Add("Laravel");
                    if (low.Contains("aspxauth") || low.Contains("asp.net_sessionid")) TechDetections.Add("ASP.NET");
                    if (low.Contains("_shopify") || low.Contains("shopify")) TechDetections.Add("Shopify");
                    if (low.Contains("wordpress_") || low.Contains("wp-settings") || low.Contains("woocommerce")) TechDetections.Add("WordPress");
                    if (low.Contains("xsrf-token")) TechDetections.Add("Angular");
                }
                try { RecordCookies(baseUri.Host, headResp); } catch { }
            }
            // Apply header/cookie/meta rules (typed + optional JSON)
            TechSignatureCatalog.ApplyHeadersCookiesMeta(headResp, body, TechDetections, TechDetails);
            // Optional JSON extension rules
            ApplyHeaderCookieMetaRules(headResp, body);
            // CORS and Server-Timing posture (first-party only)
            try { RecordCorsHeaders(baseUri.Host, headResp); } catch { }
            try { RecordServerTiming(baseUri.Host, headResp); } catch { }
        } catch { }

        DetectTechFromHeadersAndBody(MainHttpAnalysis, body);
        logger?.WriteProgress("WEBSTATIC", "Discover resources", 20.0, 1, 6);

        // Discover link hints and structured data in main HTML (no network activity)
        try { ParseLinkHintsFromBody(baseUri, body); } catch { }
        try { ParseStructuredDataFromBody(body); } catch { }

        var (schedule, seen) = await DiscoverResourcesAndBuildSchedule(baseUri, body, http, logger, cancellationToken);
        logger?.WriteVerbose("[WEB] Discovered {0} resource candidates", schedule?.Count ?? 0);
        logger?.WriteProgress("WEBSTATIC", "Fetch resource headers", 40.0, 2, 6);
        var (cssCandidates, hostCounts) = await FetchResourceHeadersAsync(schedule, http, logger, cancellationToken);
        logger?.WriteVerbose("[WEB] CSS candidates: {0}", cssCandidates.Count);
        logger?.WriteProgress("WEBSTATIC", "Process CSS", 55.0, 3, 6);
        await ProcessCssAsync(cssCandidates, seen, hostCounts, http, logger, cancellationToken);
        logger?.WriteProgress("WEBSTATIC", "Enrich hosts (TLS/DNS)", 75.0, 4, 6);
        await EnrichHostsAsync(logger, cancellationToken);

        // 6) First/third-party classification + trackers
        foreach (var kv in Hosts)
        {
            kv.Value.FirstParty = !string.IsNullOrWhiteSpace(PrimaryRegistrableDomain) &&
                                   string.Equals(kv.Value.RegistrableDomain ?? kv.Key, PrimaryRegistrableDomain, StringComparison.OrdinalIgnoreCase);
            if (IsTracker(kv.Value.RegistrableDomain ?? kv.Key))
            {
                TrackersUsed.Add(kv.Value.RegistrableDomain ?? kv.Key);
            }
        }
        logger?.WriteProgress("WEBSTATIC", "Apply detections", 90.0, 5, 6);
        // 7) Apply path/domain/body rules (typed + optional JSON)
        TechSignatureCatalog.ApplyPathsDomainsBody(Requests, Hosts, MainHttpAnalysis?.Body, GetRegistrableDomain, TechDetections, TechDetails);
        // Optional JSON extension rules for paths/domains/body
        ApplyPathAndDomainRules();
        // 8) Lightweight DNS TXT detections for verification records
        await ApplyDnsTechDetections(baseUri.Host, cancellationToken).ConfigureAwait(false);
        logger?.WriteVerbose("[WEB] Hosts: {0}; Requests: {1}; Tech: {2}; Trackers: {3}", Hosts.Count, Requests.Count, TechDetections.Count, TrackersUsed.Count);
        logger?.WriteProgress("WEBSTATIC", "Done", 100.0, 6, 6);
        logger?.WriteVerbose("[WEB] Static scan completed: {0}", url);
    }

    /// <summary>
    /// Applies heuristic detections from headers/body beyond the rules (e.g., server/cookie hints and generator meta).
    /// </summary>
    private void DetectTechFromHeadersAndBody(HttpAnalysis main, string? body)
    {
        ApplyHeuristicDetections(main, body);
    }
    // DNS TXT verification handling moved to partial (WebStaticScanAnalysis.Dns.cs)
}
