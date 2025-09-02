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
        /// <summary>Edge/CDN provider inferred from headers (e.g., Cloudflare, CloudFront, Fastly, Azure Front Door).</summary>
        public string? EdgeProvider { get; set; }
        /// <summary>Edge Point-of-Presence code when available (e.g., CF-RAY suffix or X-Amz-Cf-Pop).</summary>
        public string? EdgePop { get; set; }
        /// <summary>Edge cache status when available (e.g., HIT/MISS).</summary>
        public string? EdgeCacheStatus { get; set; }
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

    // Regex helpers moved to Regexes partial

    public async Task Analyze(string url, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        Subject = url;
        Requests.Clear();
        Hosts.Clear();
        _cookiesSet = 0;

        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "WEBSTATIC", target: url);
        using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true }) { Timeout = Timeout };
        Uri baseUri = new Uri(url);
        PrimaryRegistrableDomain = GetRegistrableDomain?.Invoke(baseUri.Host) ?? baseUri.Host;

        // 1) Reuse HttpAnalysis for main document posture
        MainHttpAnalysis = new HttpAnalysis();
        await MainHttpAnalysis.AnalyzeUrl(url, checkHsts: true, logger: logger, collectHeaders: true, captureBody: true, cancellationToken);
        string? body = MainHttpAnalysis.Body;
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
            // Cookies → framework hints
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
            }
            // Apply header/cookie/meta rules (typed + optional JSON)
            TechSignatureCatalog.ApplyHeadersCookiesMeta(headResp, body, TechDetections, TechDetails);
            // Optional JSON extension rules
            ApplyHeaderCookieMetaRules(headResp, body);
        } catch { }

        DetectTechFromHeadersAndBody(MainHttpAnalysis, body);

        var (schedule, seen) = await DiscoverResourcesAndBuildSchedule(baseUri, body, http, cancellationToken);
        var (cssCandidates, hostCounts) = await FetchResourceHeadersAsync(schedule, http, cancellationToken);
        await ProcessCssAsync(cssCandidates, seen, hostCounts, http, cancellationToken);
        await EnrichHostsAsync(cancellationToken);

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
        // 7) Apply path/domain/body rules (typed + optional JSON)
        TechSignatureCatalog.ApplyPathsDomainsBody(Requests, Hosts, MainHttpAnalysis?.Body, GetRegistrableDomain, TechDetections, TechDetails);
        // Optional JSON extension rules for paths/domains/body
        ApplyPathAndDomainRules();
        // 8) Lightweight DNS TXT detections for verification records
        await ApplyDnsTechDetections(baseUri.Host, cancellationToken).ConfigureAwait(false);
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
