using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Discovery and initial header fetching for WebStaticScanAnalysis.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private async Task<(List<string> schedule, HashSet<string> seen)> DiscoverResourcesAndBuildSchedule(Uri baseUri, string? body, HttpClient http, InternalLogger logger, CancellationToken cancellationToken)
    {
        logger?.WriteVerbose("[WEB] Discover from HTML ...");
        var discovered = new List<string>();
        WebStaticScanAnalysis.RobotsRules? robots = null;
        if (RespectRobots)
        {
            try { robots = await GetRobotsRulesAsync(baseUri, http, cancellationToken).ConfigureAwait(false); } catch { }
        }
        if (!string.IsNullOrEmpty(body))
        {
            foreach (Match m in _attrRegex.Matches(body))
            {
                var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : null;
                if (string.IsNullOrWhiteSpace(v)) continue;
                v = v.Trim();
                if (v.StartsWith("#") || v.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)) continue;
                try
                {
                    var absolute = new Uri(baseUri, v);
                    if (absolute.Scheme == Uri.UriSchemeHttp || absolute.Scheme == Uri.UriSchemeHttps)
                    {
                        // robots.txt filtering using parsed rules
                        if (robots != null)
                        {
                            var path = absolute.AbsolutePath;
                            if (!robots.IsAllowed(path)) continue;
                        }
                        // First-party only filtering
                        if (SkipThirdParty)
                        {
                            try
                            {
                                var baseDom = PrimaryRegistrableDomain ?? baseUri.Host;
                                var hostDom = GetRegistrableDomain?.Invoke(absolute.Host) ?? absolute.Host;
                                if (!string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase)) continue;
                            }
                            catch { }
                        }
                        discovered.Add(absolute.AbsoluteUri);
                    }
                }
                catch { }
                if (discovered.Count >= MaxResources) break;
            }
        }
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
            catch { }
        }
        var schedule = new List<string>(unique.Length);
        while (buckets.Count > 0)
        {
            foreach (var kv in buckets.ToArray())
            {
                if (kv.Value.Count > 0) schedule.Add(kv.Value.Dequeue());
                if (kv.Value.Count == 0) buckets.Remove(kv.Key);
            }
        }
        logger?.WriteVerbose("[WEB] Discovery complete: {0} unique", schedule.Count);
        return (schedule, seen);
    }

    private async Task<(ConcurrentBag<string> cssCandidates, ConcurrentDictionary<string, int> hostCounts)> FetchResourceHeadersAsync(List<string> schedule, HttpClient http, InternalLogger logger, CancellationToken cancellationToken)
    {
        var cssCandidates = new ConcurrentBag<string>();
        var hostCounts = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int cap = Math.Max(1, (DiscoveryConcurrency > 0 ? DiscoveryConcurrency : Concurrency));
        using var gate = new SemaphoreSlim(cap);
        logger?.WriteVerbose("[WEB] Fetching headers for {0} resources (cap={1})", schedule.Count, cap);
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
                    var current = hostCounts.AddOrUpdate(host, 1, (_, c) => c + 1);
                    if (current > MaxResourcesPerHost) return;
                    var req = new StaticRequest { Url = res, Method = "HEAD", Source = "HTML", SourceKind = ResourceSourceKind.Html };
                    try
                    {
                        using var head = new HttpRequestMessage(HttpMethod.Head, res);
                        var _start = System.DateTimeOffset.UtcNow; var _sw = System.Diagnostics.Stopwatch.StartNew();
                        using var resp = await http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                        _sw.Stop(); var _end = _start.Add(_sw.Elapsed);
                        req.StatusCode = (int)resp.StatusCode;
                        req.StatusClass = ToStatusClass(req.StatusCode);
                        req.ContentType = resp.Content?.Headers?.ContentType?.MediaType ?? resp.Content?.Headers?.ContentType?.ToString();
                        req.ContentSupertype = ToMediaSupertype(req.ContentType);
                        req.ContentLength = resp.Content?.Headers?.ContentLength;
                        req.FinalUrl = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? res;
                        req.StartedAtUtc = _start; req.CompletedAtUtc = _end; req.HeaderDurationMs = (int)_sw.Elapsed.TotalMilliseconds;
                        FillResponseMeta(req, resp);
                        try {
                            req.WasRedirected = !string.Equals(req.FinalUrl ?? req.Url, req.Url, System.StringComparison.OrdinalIgnoreCase);
                            if (req.WasRedirected)
                            {
                                var fromU = new Uri(res); var toU = new Uri(req.FinalUrl ?? req.Url);
                                req.RedirectKind = ClassifyRedirect(fromU, toU);
                                req.RedirectHopCount = 1;
                                req.RedirectToHost = toU.Host; req.RedirectToScheme = toU.Scheme;
                                RecordRedirect(host, req);
                            }
                        } catch { req.WasRedirected = false; }
                        if (resp.Headers.TryGetValues("Set-Cookie", out var _)) { System.Threading.Interlocked.Increment(ref _cookiesSet); try { RecordCookies(host, resp); } catch { } }
                        try {
                            lock (_sync) {
                                if (Hosts.TryGetValue(host, out var hh)) {
                                    if (string.IsNullOrWhiteSpace(hh.ServerHeader) && resp.Headers.TryGetValues("Server", out var sh)) hh.ServerHeader = System.Linq.Enumerable.FirstOrDefault(sh);
                                    if (!hh.HostHstsPresent && (resp.Headers.Contains("Strict-Transport-Security") || resp.Content.Headers.Contains("Strict-Transport-Security"))) hh.HostHstsPresent = true;
                                }
                            }
                        } catch { }
                        // Capture provider hints and policy headers for this host
                        try { lock (_sync) { if (Hosts.TryGetValue(host, out var hh)) CaptureEdgeHints(resp, hh); } } catch { }
                        try { RecordCorsHeaders(host, resp); } catch { }
                        try { RecordServerTiming(host, resp); } catch { }
                        try { RecordCacheHeaders(host, resp); } catch { }
                        try { RecordHeaderFrequency(host, resp); } catch { }
                    }
                    catch
                    {
                        try
                        {
                            req.Method = "GET";
                            var _start = System.DateTimeOffset.UtcNow; var _sw = System.Diagnostics.Stopwatch.StartNew();
                            using var get = await http.GetAsync(res, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                            _sw.Stop(); var _end = _start.Add(_sw.Elapsed);
                            req.StatusCode = (int)get.StatusCode;
                            req.StatusClass = ToStatusClass(req.StatusCode);
                            req.ContentType = get.Content?.Headers?.ContentType?.MediaType ?? get.Content?.Headers?.ContentType?.ToString();
                            req.ContentSupertype = ToMediaSupertype(req.ContentType);
                            req.ContentLength = get.Content?.Headers?.ContentLength;
                            req.FinalUrl = get.RequestMessage?.RequestUri?.AbsoluteUri ?? res;
                            req.StartedAtUtc = _start; req.CompletedAtUtc = _end; req.HeaderDurationMs = (int)_sw.Elapsed.TotalMilliseconds;
                            FillResponseMeta(req, get);
                            try {
                                req.WasRedirected = !string.Equals(req.FinalUrl ?? req.Url, req.Url, System.StringComparison.OrdinalIgnoreCase);
                                if (req.WasRedirected)
                                {
                                    var fromU = new Uri(res); var toU = new Uri(req.FinalUrl ?? req.Url);
                                    req.RedirectKind = ClassifyRedirect(fromU, toU);
                                    req.RedirectHopCount = 1;
                                    req.RedirectToHost = toU.Host; req.RedirectToScheme = toU.Scheme;
                                    RecordRedirect(host, req);
                                }
                            } catch { req.WasRedirected = false; }
                            if (get.Headers.TryGetValues("Set-Cookie", out var _)) { System.Threading.Interlocked.Increment(ref _cookiesSet); try { RecordCookies(host, get); } catch { } }
                            try {
                                lock (_sync) {
                                    if (Hosts.TryGetValue(host, out var hh)) {
                                        if (string.IsNullOrWhiteSpace(hh.ServerHeader) && get.Headers.TryGetValues("Server", out var sh)) hh.ServerHeader = System.Linq.Enumerable.FirstOrDefault(sh);
                                        if (!hh.HostHstsPresent && (get.Headers.Contains("Strict-Transport-Security") || get.Content.Headers.Contains("Strict-Transport-Security"))) hh.HostHstsPresent = true;
                                    }
                                }
                            } catch { }
                            // Capture provider hints and policy headers for this host
                            try { lock (_sync) { if (Hosts.TryGetValue(host, out var hh)) CaptureEdgeHints(get, hh); } } catch { }
                            try { RecordCorsHeaders(host, get); } catch { }
                            try { RecordServerTiming(host, get); } catch { }
                            try { RecordCacheHeaders(host, get); } catch { }
                            try { RecordHeaderFrequency(host, get); } catch { }
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
                        req.Id = System.Threading.Interlocked.Increment(ref _requestIdSeed);
                        req.ParentId = Requests.Count > 0 ? Requests[0].Id : (int?)null;
                        Requests.Add(req);
                        _requestIdByUrl.TryAdd(req.Url, req.Id);
                        if (!string.IsNullOrWhiteSpace(req.FinalUrl)) _requestIdByUrl.TryAdd(req.FinalUrl, req.Id);
                        if (!Hosts.TryGetValue(req.Host, out var h))
                        {
                            h = new StaticHost { Host = req.Host, RegistrableDomain = GetRegistrableDomain?.Invoke(req.Host) };
                            Hosts[req.Host] = h;
                        }
                        if (h.GroupId == 0) h.GroupId = System.Threading.Interlocked.Increment(ref _hostGroupSeed);
                        h.RequestCount++;
                        req.HostGroupId = h.GroupId;
                        req.CategoryKind = ToCategoryKind(Categorize(req.FinalUrl ?? req.Url, req.ContentType));
                        if (req.ContentLength.HasValue)
                        {
                            h.Bytes += req.ContentLength.Value;
                            var catKey = CategoryKey(req.CategoryKind);
                            h.BytesByType[catKey] = h.BytesByType.TryGetValue(catKey, out var bv) ? bv + req.ContentLength.Value : req.ContentLength.Value;
                            BytesByType[catKey] = BytesByType.TryGetValue(catKey, out var v) ? v + req.ContentLength.Value : req.ContentLength.Value;
                        }
                        try
                        {
                            var baseDom = PrimaryRegistrableDomain ?? targetUri.Host;
                            var hostDom = GetRegistrableDomain?.Invoke(req.Host) ?? req.Host;
                            req.FirstParty = string.Equals(baseDom, hostDom, System.StringComparison.OrdinalIgnoreCase);
                            // Stamp TLS if available already (may get refined after enrichment)
                            if (Hosts.TryGetValue(req.Host, out var hTls) && hTls?.Tls != null)
                            {
                                req.TlsProtocol = hTls.Tls.Protocol.ToString();
                                req.TlsCipherSuite = hTls.Tls.CipherSuite;
                                try
                                {
                                    req.TlsCertSubject = hTls.Tls.CertificateSubject;
                                    req.TlsCertIssuer = hTls.Tls.CertificateIssuer;
                                    req.TlsCertNotAfter = hTls.Tls.NotAfter;
                                    req.TlsCertThumbprint = hTls.Tls.Certificate?.Thumbprint;
                                }
                                catch { }
                            }
                            try { if (MainFinalUri != null) { var fu = new Uri(req.FinalUrl ?? req.Url); req.SameOrigin = fu.Scheme == MainFinalUri.Scheme && fu.Host == MainFinalUri.Host && fu.Port == MainFinalUri.Port; } } catch { }
                        } catch { req.FirstParty = false; }
                        AddAdjacency(req.ParentId, req.Id);
                    }
                }
                finally
                {
                    try { gate.Release(); } catch { }
                }
            }, cancellationToken));
        }
        await Task.WhenAll(tasks);
        logger?.WriteVerbose("[WEB] Header fetch complete. CSS candidates: {0}", cssCandidates.Count);
        return (cssCandidates, hostCounts);
    }
}
