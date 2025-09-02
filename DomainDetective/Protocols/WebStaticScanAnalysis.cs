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
    // Link checking controls
    public bool FollowLinks { get; set; } = false;
    public int LinkMaxDepth { get; set; } = 0;
    public int LinkMaxPages { get; set; } = 100;
    public bool LinkFirstPartyOnly { get; set; } = true;
    public int LinkConcurrency { get; set; } = 0;
    /// <summary>When true, skips static resource discovery and performs link checks only.</summary>
    public bool LinkOnly { get; set; } = false;

    

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
    /// <summary>Structured tracker detections with evidence instead of plain strings.</summary>
    public System.Collections.Generic.List<TrackerDetection> TrackerDetails { get; } = new System.Collections.Generic.List<TrackerDetection>();
    /// <summary>List of broken resources (HTTP status >= 400 or failed) discovered during the scan.</summary>
    public System.Collections.Generic.List<BrokenResource> BrokenResources { get; } = new System.Collections.Generic.List<BrokenResource>();

    

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
        // Add main document as the first request entry for waterfall/ordering
        try
        {
            var mainVisited = MainHttpAnalysis?.VisitedUrls;
            var finalUrl = (mainVisited != null && mainVisited.Count > 0) ? mainVisited[mainVisited.Count - 1] : url;
            var finalUri = new Uri(finalUrl);
            var host = finalUri.Host;
            var reqMain = new StaticRequest
            {
                Url = url,
                FinalUrl = finalUrl,
                Host = host,
                Method = "GET",
                StatusCode = MainHttpAnalysis?.StatusCode ?? 0,
                StatusClass = ToStatusClass(MainHttpAnalysis?.StatusCode ?? 0),
                ProtocolVersion = MainHttpAnalysis?.ProtocolVersion?.ToString(),
                Http2 = MainHttpAnalysis?.Http2Supported == true,
                Http3 = MainHttpAnalysis?.Http3Supported == true,
                ContentType = null,
                ContentSupertype = MediaSupertype.Unknown,
                ContentLength = (MainHttpAnalysis?.BodyLength.HasValue == true ? (long?)MainHttpAnalysis.BodyLength.Value : null),
                CategoryKind = ResourceCategory.Document,
                Source = "MAIN",
                SourceKind = ResourceSourceKind.Html,
                Referrer = null,
                Depth = 0,
                FirstParty = true,
                StartedAtUtc = System.DateTimeOffset.UtcNow - (MainHttpAnalysis?.ResponseTime ?? System.TimeSpan.Zero),
                CompletedAtUtc = System.DateTimeOffset.UtcNow,
                HeaderDurationMs = (int?)(MainHttpAnalysis?.ResponseTime.TotalMilliseconds)
            };
            lock (_sync)
            {
                Requests.Insert(0, reqMain);
                if (!Hosts.TryGetValue(host, out var h))
                {
                    h = new StaticHost { Host = host, RegistrableDomain = GetRegistrableDomain?.Invoke(host) };
                    Hosts[host] = h;
                }
                h.RequestCount++;
                // classify first/third party later globally; set FirstParty true for main
                h.FirstParty = true;
                if (reqMain.ContentLength.HasValue)
                {
                    h.Bytes += reqMain.ContentLength.Value;
                    var catKey = CategoryKey(reqMain.CategoryKind);
                    h.BytesByType[catKey] = h.BytesByType.TryGetValue(catKey, out var bv) ? bv + reqMain.ContentLength.Value : reqMain.ContentLength.Value;
                    BytesByType[catKey] = BytesByType.TryGetValue(catKey, out var v) ? v + reqMain.ContentLength.Value : reqMain.ContentLength.Value;
                }
            }
        }
        catch { }
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

        if (LinkOnly)
        {
            // Link-only mode: skip static resource discovery and CSS; perform bounded link checks only.
            try { await CheckLinksAsync(baseUri, body, http, logger, cancellationToken); } catch { }
        }
        else
        {
            var (schedule, seen) = await DiscoverResourcesAndBuildSchedule(baseUri, body, http, logger, cancellationToken);
            logger?.WriteVerbose("[WEB] Discovered {0} resource candidates", schedule?.Count ?? 0);
            logger?.WriteProgress("WEBSTATIC", "Fetch resource headers", 40.0, 2, 6);
            var (cssCandidates, hostCounts) = await FetchResourceHeadersAsync(schedule, http, logger, cancellationToken);
            logger?.WriteVerbose("[WEB] CSS candidates: {0}", cssCandidates.Count);
            logger?.WriteProgress("WEBSTATIC", "Process CSS", 55.0, 3, 6);
            await ProcessCssAsync(cssCandidates, seen, hostCounts, http, logger, cancellationToken);
            // Optional link checking (bounded depth/pages)
            try { await CheckLinksAsync(baseUri, body, http, logger, cancellationToken); } catch { }
            logger?.WriteProgress("WEBSTATIC", "Enrich hosts (TLS/DNS)", 75.0, 4, 6);
            await EnrichHostsAsync(logger, cancellationToken);
        }

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
        // Build structured tracker details after classification
        BuildTrackerDetails();
        // Broken resource list (status >= 400 or failed)
        try
        {
            BrokenResources.Clear();
            foreach (var r in Requests)
            {
                if (r == null) continue;
                var sc = r.StatusCode;
                if (sc >= 400 || sc == 0)
                {
                    var host = r.Host ?? (new Uri(r.FinalUrl ?? r.Url)).Host;
                    bool fp = false; try { fp = Hosts.TryGetValue(host, out var hh) ? hh.FirstParty : string.Equals(GetRegistrableDomain?.Invoke(host) ?? host, PrimaryRegistrableDomain ?? host, StringComparison.OrdinalIgnoreCase); } catch { }
                    string cat = CategoryKey(r.CategoryKind);
                    BrokenResources.Add(new BrokenResource
                    {
                        Url = r.Url,
                        FinalUrl = r.FinalUrl,
                        StatusCode = sc,
                        Host = host,
                        Category = cat,
                        Source = r.Source,
                        Referrer = r.Referrer,
                        FirstParty = fp
                    });
                }
            }
        }
        catch { }
        logger?.WriteProgress("WEBSTATIC", "Apply detections", 90.0, 5, 6);
        // 7) Apply path/domain/body rules (typed + optional JSON)
        TechSignatureCatalog.ApplyPathsDomainsBody(Requests, Hosts, MainHttpAnalysis?.Body, GetRegistrableDomain, TechDetections, TechDetails);
        // Optional JSON extension rules for paths/domains/body
        ApplyPathAndDomainRules();
        // 8) Lightweight DNS TXT detections for verification records
        await ApplyDnsTechDetections(baseUri.Host, cancellationToken).ConfigureAwait(false);
        // 9) Ensure every TechDetections entry has provenance in TechDetails
        EnsureTechDetailsForAllDetections(MainHttpAnalysis?.Body, MainHttpAnalysis);
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
