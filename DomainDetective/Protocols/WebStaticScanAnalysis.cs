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
public class WebStaticScanAnalysis : IHasAssessments
{
    public string? Subject { get; set; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
    public int MaxResources { get; set; } = 300;
    public int Concurrency { get; set; } = 8;
    public bool RespectRobots { get; set; } = false;
    public bool EnableThreatIntel { get; set; } = false;
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

    private static readonly Regex _attrRegex = new(@"(?i)(?:src|href)\s*=\s*""([^""]+)""|(?:src|href)\s*=\s*'([^']+)'", RegexOptions.Compiled);
    private static readonly Regex _cssUrlRegex = new(@"(?i)url\((?:""([^""]+)""|'([^']+)'|([^)]+))\)", RegexOptions.Compiled);
    private static readonly Regex _cssImportRegex = new(@"(?i)@import\s+(?:url\(([^)]+)\)|""([^""]+)""|'([^']+)')", RegexOptions.Compiled);
    private static readonly string[] _resourceTags = new[] { "script", "img", "link", "iframe", "source" };

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

        // 2) Discover resource URLs from HTML (simple attribute scan)
        var discovered = new List<string>();
        if (!string.IsNullOrEmpty(body))
        {
            foreach (Match m in _attrRegex.Matches(body))
            {
                var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : null;
                if (string.IsNullOrWhiteSpace(v)) continue;
                v = v.Trim();
                // Skip anchors and javascript: links
                if (v.StartsWith("#") || v.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var absolute = new Uri(baseUri, v);
                    if (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
                    {
                        discovered.Add(absolute.AbsoluteUri);
                    }
                }
                catch { }
                if (discovered.Count >= MaxResources) break;
            }
        }

        // Deduplicate and build a fair (round-robin) schedule across hosts
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var unique = discovered.Where(u => seen.Add(u)).Take(MaxResources).ToArray();
        var buckets = new Dictionary<string, Queue<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var u in unique)
        {
            try
            {
                var h = new Uri(u).Host;
                if (!buckets.TryGetValue(h, out var q)) { q = new Queue<string>(); buckets[h] = q; }
                q.Enqueue(u);
            }
            catch { /* ignore malformed */ }
        }
        var schedule = new List<string>(unique.Length);
        while (buckets.Count > 0)
        {
            foreach (var kv in buckets.ToArray())
            {
                if (kv.Value.Count > 0)
                {
                    schedule.Add(kv.Value.Dequeue());
                }
                if (kv.Value.Count == 0)
                {
                    buckets.Remove(kv.Key);
                }
            }
        }

        // 3) Fetch resource headers (HEAD then small GET fallback) with bounded concurrency and per-host caps
        var cssCandidates = new System.Collections.Concurrent.ConcurrentBag<string>();
        var hostCounts = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        using (var gate = new System.Threading.SemaphoreSlim(Math.Max(1, Concurrency)))
        {
            var tasks = new List<Task>(schedule.Count);
            foreach (var res in schedule)
            {
                await gate.WaitAsync(cancellationToken);
                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var targetUri = new Uri(res);
                        var host = targetUri.Host;
                        // Per-host cap
                        var current = hostCounts.AddOrUpdate(host, 1, (_, c) => c + 1);
                        if (current > MaxResourcesPerHost)
                        {
                            return;
                        }
                        var req = new StaticRequest { Url = res, Method = "HEAD" };
                        try
                        {
                            using var head = new HttpRequestMessage(HttpMethod.Head, res);
                            using var resp = await http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                            req.StatusCode = (int)resp.StatusCode;
                            req.ContentType = resp.Content?.Headers?.ContentType?.MediaType ?? resp.Content?.Headers?.ContentType?.ToString();
                            req.ContentLength = resp.Content?.Headers?.ContentLength;
                            req.FinalUrl = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? res;
                            if (resp.Headers.TryGetValues("Set-Cookie", out var _)) System.Threading.Interlocked.Increment(ref _cookiesSet);
                        }
                        catch
                        {
                            try
                            {
                                req.Method = "GET";
                                using var get = await http.GetAsync(res, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                                req.StatusCode = (int)get.StatusCode;
                                req.ContentType = get.Content?.Headers?.ContentType?.MediaType ?? get.Content?.Headers?.ContentType?.ToString();
                                req.ContentLength = get.Content?.Headers?.ContentLength;
                                req.FinalUrl = get.RequestMessage?.RequestUri?.AbsoluteUri ?? res;
                                if (get.Headers.TryGetValues("Set-Cookie", out var _)) System.Threading.Interlocked.Increment(ref _cookiesSet);
                            }
                            catch { }
                        }
                        try
                        {
                            var final = new Uri(req.FinalUrl ?? req.Url);
                            req.Host = final.Host;
                            if ((req.ContentType != null && req.ContentType.IndexOf("text/css", StringComparison.OrdinalIgnoreCase) >= 0) ||
                                final.AbsolutePath.EndsWith(".css", StringComparison.OrdinalIgnoreCase))
                            {
                                cssCandidates.Add(req.FinalUrl ?? req.Url);
                            }
                        }
                        catch { req.Host = host; }

                        lock (_sync)
                        {
                            Requests.Add(req);
                            if (!Hosts.TryGetValue(req.Host, out var h))
                            {
                                h = new StaticHost { Host = req.Host, RegistrableDomain = GetRegistrableDomain?.Invoke(req.Host) };
                                Hosts[req.Host] = h;
                            }
                            h.RequestCount++;
                            if (req.ContentLength.HasValue)
                            {
                                h.Bytes += req.ContentLength.Value;
                                var cat = Categorize(req.FinalUrl ?? req.Url, req.ContentType);
                                if (!string.IsNullOrEmpty(cat))
                                {
                                    h.BytesByType[cat] = h.BytesByType.TryGetValue(cat, out var bv) ? bv + req.ContentLength.Value : req.ContentLength.Value;
                                    BytesByType[cat] = BytesByType.TryGetValue(cat, out var v) ? v + req.ContentLength.Value : req.ContentLength.Value;
                                }
                            }
                        }
                    }
                    finally
                    {
                        try { gate.Release(); } catch { }
                    }
                }, cancellationToken));
            }
            await Task.WhenAll(tasks);
        }

        // 3b) Fetch CSS bodies (capped) and extract url()/@import resources
        const int MaxCssBytes = 128 * 1024;
        foreach (var css in cssCandidates.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var response = await http.GetAsync(css, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                if (response.Headers.TryGetValues("Set-Cookie", out var _)) System.Threading.Interlocked.Increment(ref _cookiesSet);
                using var stream = await response.Content.ReadAsStreamAsync();
                using var limited = new System.IO.MemoryStream();
                var buffer = new byte[16 * 1024];
                int read; int total = 0;
                while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0 && total < MaxCssBytes)
                {
                    limited.Write(buffer, 0, read);
                    total += read;
                }
                var text = System.Text.Encoding.UTF8.GetString(limited.ToArray());
                foreach (Match m in _cssUrlRegex.Matches(text))
                {
                    var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                    var val = (v ?? string.Empty).Trim().Trim('\'', '"');
                    if (string.IsNullOrWhiteSpace(val)) continue;
                    if (val.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        var abs = new Uri(new Uri(css), val);
                        if ((abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps) && seen.Add(abs.AbsoluteUri) && Requests.Count < MaxResources)
                        {
                            // schedule lightweight HEAD
                            var headReq = new StaticRequest { Url = abs.AbsoluteUri, Method = "HEAD" };
                            try
                            {
                                using var head = new HttpRequestMessage(HttpMethod.Head, abs);
                                using var resp = await http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                                headReq.StatusCode = (int)resp.StatusCode;
                                headReq.ContentType = resp.Content?.Headers?.ContentType?.MediaType ?? resp.Content?.Headers?.ContentType?.ToString();
                                headReq.ContentLength = resp.Content?.Headers?.ContentLength;
                                headReq.FinalUrl = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? abs.AbsoluteUri;
                            }
                            catch { headReq.Method = "GET"; }
                            try { headReq.Host = new Uri(headReq.FinalUrl ?? headReq.Url).Host; } catch { headReq.Host = abs.Host; }
                            // Per-host cap during CSS pass
                            var cur = hostCounts.AddOrUpdate(headReq.Host, 1, (_, c) => c + 1);
                            if (cur <= MaxResourcesPerHost)
                            {
                                lock (_sync)
                                {
                                    if (Requests.Count < MaxResources)
                                    {
                                        Requests.Add(headReq);
                                        if (!Hosts.TryGetValue(headReq.Host, out var host2))
                                        {
                                            host2 = new StaticHost { Host = headReq.Host, RegistrableDomain = GetRegistrableDomain?.Invoke(headReq.Host) };
                                            Hosts[headReq.Host] = host2;
                                        }
                                        host2.RequestCount++;
                                        if (headReq.ContentLength.HasValue)
                                        {
                                            host2.Bytes += headReq.ContentLength.Value;
                                            var cat2 = Categorize(headReq.FinalUrl ?? headReq.Url, headReq.ContentType);
                                            if (!string.IsNullOrEmpty(cat2))
                                            {
                                                host2.BytesByType[cat2] = host2.BytesByType.TryGetValue(cat2, out var hb) ? hb + headReq.ContentLength.Value : headReq.ContentLength.Value;
                                                BytesByType[cat2] = BytesByType.TryGetValue(cat2, out var vb) ? vb + headReq.ContentLength.Value : headReq.ContentLength.Value;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
                foreach (Match m in _cssImportRegex.Matches(text))
                {
                    var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                    var val = (v ?? string.Empty).Trim().Trim('\'', '"');
                    if (string.IsNullOrWhiteSpace(val) || val.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) continue;
                    try
                    {
                        var abs = new Uri(new Uri(css), val);
                        if ((abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps) && seen.Add(abs.AbsoluteUri) && Requests.Count < MaxResources)
                        {
                            var headReq = new StaticRequest { Url = abs.AbsoluteUri, Method = "HEAD" };
                            try
                            {
                                using var head = new HttpRequestMessage(HttpMethod.Head, abs);
                                using var resp = await http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                                headReq.StatusCode = (int)resp.StatusCode;
                                headReq.ContentType = resp.Content?.Headers?.ContentType?.MediaType ?? resp.Content?.Headers?.ContentType?.ToString();
                                headReq.ContentLength = resp.Content?.Headers?.ContentLength;
                                headReq.FinalUrl = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? abs.AbsoluteUri;
                            }
                            catch { headReq.Method = "GET"; }
                            try { headReq.Host = new Uri(headReq.FinalUrl ?? headReq.Url).Host; } catch { headReq.Host = abs.Host; }
                            Requests.Add(headReq);
                            if (!Hosts.TryGetValue(headReq.Host, out var host2))
                            {
                                host2 = new StaticHost { Host = headReq.Host, RegistrableDomain = GetRegistrableDomain?.Invoke(headReq.Host) };
                                Hosts[headReq.Host] = host2;
                            }
                            host2.RequestCount++;
                            if (headReq.ContentLength.HasValue)
                            {
                                host2.Bytes += headReq.ContentLength.Value;
                                var cat2 = Categorize(headReq.FinalUrl ?? headReq.Url, headReq.ContentType);
                                if (!string.IsNullOrEmpty(cat2))
                                {
                                    host2.BytesByType[cat2] = host2.BytesByType.TryGetValue(cat2, out var hb) ? hb + headReq.ContentLength.Value : headReq.ContentLength.Value;
                                    BytesByType[cat2] = BytesByType.TryGetValue(cat2, out var vb) ? vb + headReq.ContentLength.Value : headReq.ContentLength.Value;
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        // 4) TLS probe per unique host (best-effort)
        foreach (var kv in Hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                kv.Value.Tls = await TlsProbe.ProbeAsync(kv.Key, 443, cancellationToken);
            }
            catch { }
        }

        // 5) Per-host DNS resolution (A/AAAA) and optional RDAP IP info (CIDR/ASN/country)
        foreach (var kv in Hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var answers4 = await DnsConfiguration.QueryDNS(kv.Key, DnsRecordType.A, cancellationToken: cancellationToken);
                var answers6 = await DnsConfiguration.QueryDNS(kv.Key, DnsRecordType.AAAA, cancellationToken: cancellationToken);
                foreach (var a in answers4.Concat(answers6))
                {
                    var ip = a.Data ?? a.DataRaw;
                    if (!string.IsNullOrWhiteSpace(ip) && !kv.Value.IpAddresses.Contains(ip)) kv.Value.IpAddresses.Add(ip);
                }
            }
            catch { }
            // Future: use RdapClient to get ASN/country; for now, attempt CIDR if single IP
            try
            {
                if (kv.Value.IpAddresses.Count > 0)
                {
                    var ip = kv.Value.IpAddresses[0];
                    var rdap = await new RdapClient().GetIp(ip, cancellationToken).ConfigureAwait(false);
                    kv.Value.Cidr = rdap?.Cidr;
                    kv.Value.Country = rdap?.Country;
                    if (rdap?.Entities != null)
                    {
                        foreach (var ent in rdap.Entities)
                        {
                            var handle = ent.Handle ?? string.Empty;
                            if (handle.StartsWith("AS", System.StringComparison.OrdinalIgnoreCase))
                            {
                                if (int.TryParse(handle.TrimStart('A','S','a','s'), out var asn)) kv.Value.Asn = asn;
                                // Try extract friendly name from vCard 'fn'
                                try
                                {
                                    if (ent.VcardArray.HasValue && ent.VcardArray.Value.ValueKind == System.Text.Json.JsonValueKind.Array && ent.VcardArray.Value.GetArrayLength() > 1)
                                    {
                                        foreach (var card in ent.VcardArray.Value[1].EnumerateArray())
                                        {
                                            if (card.GetArrayLength() > 3 && card[0].GetString() == "fn")
                                            {
                                                kv.Value.AsName = card[3].GetString();
                                                break;
                                            }
                                        }
                                    }
                                } catch { }
                                break;
                            }
                        }
                    }
                }
            }
            catch { }
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
        // 7) Apply path/domain/body rules (typed + optional JSON)
        TechSignatureCatalog.ApplyPathsDomainsBody(Requests, Hosts, MainHttpAnalysis?.Body, GetRegistrableDomain, TechDetections, TechDetails);
        // Optional JSON extension rules for paths/domains/body
        ApplyPathAndDomainRules();
    }

    /// <summary>
    /// Applies heuristic detections from headers/body beyond the rules (e.g., server/cookie hints and generator meta).
    /// </summary>
    private void DetectTechFromHeadersAndBody(HttpAnalysis main, string? body)
    {
        try
        {
            var server = main.ServerHeader ?? string.Empty;
            if (server.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("nginx");
            if (server.IndexOf("Apache", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("Apache");
            if (server.IndexOf("IIS", StringComparison.OrdinalIgnoreCase) >= 0 || server.IndexOf("Microsoft-IIS", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("IIS");
            if (server.IndexOf("cloudflare", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("Cloudflare");

            var html = body ?? string.Empty;
            // Meta generator
            var gen = System.Text.RegularExpressions.Regex.Match(html, "<meta[^>]*name=\\\"generator\\\"[^>]*content=\\\"([^\\\"]+)\\\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (gen.Success)
            {
                var val = gen.Groups[1].Value;
                if (!string.IsNullOrWhiteSpace(val)) TechDetections.Add(val.Split(' ')[0]);
            }
            // URL-based hints
            foreach (var req in Requests)
            {
                var p = new Uri(req.FinalUrl ?? req.Url).AbsolutePath.ToLowerInvariant();
                if (p.Contains("/wp-content/") || p.Contains("/wp-includes/")) TechDetections.Add("WordPress");
                if (p.Contains("drupal")) TechDetections.Add("Drupal");
                if (p.Contains("joomla")) TechDetections.Add("Joomla");
                if (p.Contains("shopify")) TechDetections.Add("Shopify");
                if (p.Contains("jquery")) TechDetections.Add("jQuery");
                if (p.Contains("bootstrap")) TechDetections.Add("Bootstrap");
                if (p.Contains("react") || p.Contains("react-dom")) TechDetections.Add("React");
                if (p.Contains("vue")) TechDetections.Add("Vue");
                if (p.Contains("angular") || p.Contains("angularjs")) TechDetections.Add("Angular");
            }
        } catch { }
    }

    private static readonly string[] _trackerDomains = new[]
    {
        "google-analytics.com","googletagmanager.com","doubleclick.net","facebook.net","facebook.com",
        "hotjar.com","segment.io","mixpanel.com","matomo.org","clarity.ms","optimizely.com","snowplowanalytics.com",
        "newrelic.com","googlesyndication.com"
    };
    private bool IsTracker(string hostOrDomain)
    {
        try
        {
            var dom = GetRegistrableDomain?.Invoke(hostOrDomain) ?? hostOrDomain;
            foreach (var t in _trackerDomains)
            {
                if (dom.EndsWith(t, StringComparison.OrdinalIgnoreCase)) return true;
            }
        } catch { }
        return false;
    }

    private void LoadTechRulesOnce()
    {
        // Optional JSON extension rules: not loaded by default. Only load when TechRulesPath is provided explicitly.
        if (_techRulesTried) return;
        _techRulesTried = true;
        try
        {
            string? path = TechRulesPath;
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                var json = File.ReadAllText(path);
                _techRules = JsonSerializer.Deserialize<TechRuleSet>(json, Helpers.JsonOptions.Default);
            }
        }
        catch { _techRules = null; }
    }

    /// <summary>
    /// Applies optional JSON header/cookie/meta rules (when loaded) to infer technologies.
    /// </summary>
    private void ApplyHeaderCookieMetaRules(HttpResponseMessage resp, string? body)
    {
        LoadTechRulesOnce(); if (_techRules == null) return;
        try
        {
            // Headers
            if (_techRules.Headers != null)
            {
                foreach (var rule in _techRules.Headers)
                {
                    if (string.IsNullOrEmpty(rule?.Name) || string.IsNullOrEmpty(rule.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                    if (resp.Headers.TryGetValues(rule.Name, out var vals) || resp.Content.Headers.TryGetValues(rule.Name, out vals))
                    {
                        foreach (var v in vals)
                        {
                            if (!string.IsNullOrEmpty(v) && v.IndexOf(rule.Contains, System.StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                TechDetections.Add(rule.Tech);
                            }
                        }
                    }
                }
            }
            // Cookies
            if (_techRules.Cookies != null && resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var c in cookies)
                {
                    foreach (var rule in _techRules.Cookies)
                    {
                        if (string.IsNullOrEmpty(rule?.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (!string.IsNullOrEmpty(c) && c.IndexOf(rule.Contains, System.StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            // Meta
            if (_techRules.Meta != null && !string.IsNullOrEmpty(body))
            {
                foreach (var rule in _techRules.Meta)
                {
                    if (string.IsNullOrEmpty(rule?.Name) || string.IsNullOrEmpty(rule.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                    var pattern = $"<meta[^>]*name=\"{System.Text.RegularExpressions.Regex.Escape(rule.Name)}\"[^>]*content=\"([^\"]*)\"";
                    var m = System.Text.RegularExpressions.Regex.Match(body, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success && (m.Groups[1].Value ?? string.Empty).IndexOf(rule.Contains, System.StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        TechDetections.Add(rule.Tech);
                    }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Applies optional JSON path/domain/body rules (when loaded) to infer technologies.
    /// </summary>
    private void ApplyPathAndDomainRules()
    {
        LoadTechRulesOnce(); if (_techRules == null) return;
        try
        {
            if (_techRules.Paths != null)
            {
                foreach (var req in Requests)
                {
                    var p = string.Empty;
                    try { p = new Uri(req.FinalUrl ?? req.Url).AbsolutePath; } catch { continue; }
                    foreach (var rule in _techRules.Paths)
                    {
                        if (rule == null || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (!string.IsNullOrEmpty(rule.Regex))
                        {
                            try { if (System.Text.RegularExpressions.Regex.IsMatch(p, rule.Regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase)) TechDetections.Add(rule.Tech); } catch { }
                        }
                        else if (!string.IsNullOrEmpty(rule.Contains))
                        {
                            if (p.IndexOf(rule.Contains, System.StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            if (_techRules.Domains != null)
            {
                foreach (var kv in Hosts)
                {
                    var dom = kv.Value.RegistrableDomain ?? kv.Key;
                    foreach (var rule in _techRules.Domains)
                    {
                        if (string.IsNullOrEmpty(rule?.Suffix) || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (dom.EndsWith(rule.Suffix, System.StringComparison.OrdinalIgnoreCase))
                        {
                            TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            if (_techRules.Body != null && !string.IsNullOrWhiteSpace(MainHttpAnalysis?.Body))
            {
                var html = MainHttpAnalysis.Body!;
                foreach (var rule in _techRules.Body)
                {
                    if (string.IsNullOrEmpty(rule?.Regex) || string.IsNullOrEmpty(rule.Tech)) continue;
                    try { if (System.Text.RegularExpressions.Regex.IsMatch(html, rule.Regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase)) TechDetections.Add(rule.Tech); } catch { }
                }
            }
        }
        catch { }
    }

    private static string Categorize(string url, string? contentType)
    {
        string type = (contentType ?? string.Empty).ToLowerInvariant();
        if (type.StartsWith("image/")) return "image";
        if (type.Contains("javascript") || type == "application/x-javascript") return "script";
        if (type == "text/css") return "stylesheet";
        if (type.StartsWith("font/") || type.Contains("woff") || type.Contains("truetype")) return "font";
        if (type.StartsWith("text/html") || type.StartsWith("application/xhtml")) return "document";
        if (type.Contains("json")) return "json";
        // fallback by extension
        try
        {
            var path = new Uri(url).AbsolutePath.ToLowerInvariant();
            if (path.EndsWith(".js")) return "script";
            if (path.EndsWith(".css")) return "stylesheet";
            if (path.EndsWith(".png") || path.EndsWith(".jpg") || path.EndsWith(".jpeg") || path.EndsWith(".gif") || path.EndsWith(".webp") || path.EndsWith(".svg")) return "image";
            if (path.EndsWith(".woff") || path.EndsWith(".woff2") || path.EndsWith(".ttf") || path.EndsWith(".otf")) return "font";
            if (path.EndsWith(".html") || path.EndsWith(".htm")) return "document";
            if (path.EndsWith(".json")) return "json";
        }
        catch { }
        return "other";
    }
}
