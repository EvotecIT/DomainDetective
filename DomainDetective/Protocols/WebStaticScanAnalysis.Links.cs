using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Optional link checking (follow anchor href links to a bounded depth) for WebStaticScanAnalysis.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private async Task CheckLinksAsync(Uri baseUri, string? body, HttpClient http, InternalLogger logger, CancellationToken ct)
    {
        if (!FollowLinks || string.IsNullOrWhiteSpace(body) || LinkMaxDepth <= 0 || LinkMaxPages <= 0) return;
        WebStaticScanAnalysis.RobotsRules? robots = null;
        if (RespectRobots)
        {
            try { robots = await GetRobotsRulesAsync(baseUri, http, ct).ConfigureAwait(false); } catch { }
        }
        var maxPages = Math.Max(1, LinkMaxPages);
        var maxDepth = Math.Max(0, LinkMaxDepth);
        var cap = Math.Max(1, (LinkConcurrency > 0 ? LinkConcurrency : Concurrency));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var q = new Queue<(Uri url, int depth, string referrer)>();
        foreach (System.Text.RegularExpressions.Match m in _anchorHrefRegex.Matches(body))
        {
            var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
            if (string.IsNullOrWhiteSpace(v)) continue;
            Uri abs; try { abs = new Uri(baseUri, v); } catch { continue; }
            if (abs.Scheme != Uri.UriSchemeHttp && abs.Scheme != Uri.UriSchemeHttps) continue;
            if (robots != null) { var p = abs.AbsolutePath; if (!robots.IsAllowed(p)) continue; }
            if (LinkFirstPartyOnly)
            {
                try
                {
                    var b = PrimaryRegistrableDomain ?? baseUri.Host;
                    var d = GetRegistrableDomain?.Invoke(abs.Host) ?? abs.Host;
                    if (!string.Equals(b, d, StringComparison.OrdinalIgnoreCase)) continue;
                } catch { }
            }
            if (seen.Add(abs.AbsoluteUri)) q.Enqueue((abs, 0, baseUri.AbsoluteUri));
            if (q.Count >= maxPages) break;
        }
        if (q.Count == 0) return;
        logger?.WriteVerbose("[WEB] Link-check: queued {0} links (depth<= {1})", q.Count, maxDepth);
        using var gate = new SemaphoreSlim(cap);
        var tasks = new List<Task>();
        int processed = 0;
        while (q.Count > 0 && processed < maxPages)
        {
            var (u, depth, referrer) = q.Dequeue(); processed++;
            await gate.WaitAsync(ct);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    var req = new StaticRequest { Url = u.AbsoluteUri, Method = "HEAD", Source = "LINK", SourceKind = ResourceSourceKind.Link, Referrer = referrer, Depth = depth };
                    try
                    {
                        using var head = new HttpRequestMessage(HttpMethod.Head, u);
                        var _start = System.DateTimeOffset.UtcNow; var _sw = System.Diagnostics.Stopwatch.StartNew();
                        using var resp = await http.SendAsync(head, HttpCompletionOption.ResponseHeadersRead, ct);
                        _sw.Stop(); var _end = _start.Add(_sw.Elapsed);
                        req.StatusCode = (int)resp.StatusCode;
                        req.StatusClass = ToStatusClass(req.StatusCode);
                        req.ContentType = resp.Content?.Headers?.ContentType?.MediaType ?? resp.Content?.Headers?.ContentType?.ToString();
                        req.ContentSupertype = ToMediaSupertype(req.ContentType);
                        req.ContentLength = resp.Content?.Headers?.ContentLength;
                        req.FinalUrl = resp.RequestMessage?.RequestUri?.AbsoluteUri ?? u.AbsoluteUri;
                        req.StartedAtUtc = _start; req.CompletedAtUtc = _end; req.HeaderDurationMs = (int)_sw.Elapsed.TotalMilliseconds;
                        FillResponseMeta(req, resp);
                        try {
                            req.WasRedirected = !string.Equals(req.FinalUrl ?? req.Url, req.Url, System.StringComparison.OrdinalIgnoreCase);
                            if (req.WasRedirected)
                            {
                                var fromU = new Uri(u.AbsoluteUri); var toU = new Uri(req.FinalUrl ?? req.Url);
                                req.RedirectKind = ClassifyRedirect(fromU, toU);
                                req.RedirectHopCount = 1;
                                req.RedirectToHost = toU.Host; req.RedirectToScheme = toU.Scheme;
                                RecordRedirect(u.Host, req);
                            }
                        } catch { req.WasRedirected = false; }
                        try { var freqHost = resp.RequestMessage?.RequestUri?.Host ?? u.Host; RecordHeaderFrequency(freqHost, resp); } catch { }
                    }
                    catch
                    {
                        try
                        {
                            req.Method = "GET";
                            var _start = System.DateTimeOffset.UtcNow; var _sw = System.Diagnostics.Stopwatch.StartNew();
                            using var get = await http.GetAsync(u, HttpCompletionOption.ResponseHeadersRead, ct);
                            _sw.Stop(); var _end = _start.Add(_sw.Elapsed);
                            req.StatusCode = (int)get.StatusCode;
                            req.StatusClass = ToStatusClass(req.StatusCode);
                            req.ContentType = get.Content?.Headers?.ContentType?.MediaType ?? get.Content?.Headers?.ContentType?.ToString();
                            req.ContentSupertype = ToMediaSupertype(req.ContentType);
                            req.ContentLength = get.Content?.Headers?.ContentLength;
                            req.FinalUrl = get.RequestMessage?.RequestUri?.AbsoluteUri ?? u.AbsoluteUri;
                            req.StartedAtUtc = _start; req.CompletedAtUtc = _end; req.HeaderDurationMs = (int)_sw.Elapsed.TotalMilliseconds;
                            FillResponseMeta(req, get);
                            try {
                                req.WasRedirected = !string.Equals(req.FinalUrl ?? req.Url, req.Url, System.StringComparison.OrdinalIgnoreCase);
                                if (req.WasRedirected)
                                {
                                    var fromU = new Uri(u.AbsoluteUri); var toU = new Uri(req.FinalUrl ?? req.Url);
                                    req.RedirectKind = ClassifyRedirect(fromU, toU);
                                    req.RedirectHopCount = 1;
                                    req.RedirectToHost = toU.Host; req.RedirectToScheme = toU.Scheme;
                                    RecordRedirect(u.Host, req);
                                }
                            } catch { req.WasRedirected = false; }
                            try { var freqHost = get.RequestMessage?.RequestUri?.Host ?? u.Host; RecordHeaderFrequency(freqHost, get); } catch { }
                        }
                        catch { }
                    }
                    try { req.Host = new Uri(req.FinalUrl ?? req.Url).Host; } catch { req.Host = u.Host; }
                    try { req.CategoryKind = ToCategoryKind(Categorize(req.FinalUrl ?? req.Url, req.ContentType)); } catch { }
                    try
                    {
                        var baseDom = PrimaryRegistrableDomain ?? baseUri.Host;
                        var hostDom = GetRegistrableDomain?.Invoke(req.Host) ?? req.Host;
                        req.FirstParty = string.Equals(baseDom, hostDom, System.StringComparison.OrdinalIgnoreCase);
                    } catch { req.FirstParty = false; }
                    lock (_sync)
                    {
                        req.Id = System.Threading.Interlocked.Increment(ref _requestIdSeed);
                        if (!string.IsNullOrWhiteSpace(referrer) && _requestIdByUrl.TryGetValue(referrer, out var pid)) req.ParentId = pid;
                        try { if (MainFinalUri != null) { var fu = new Uri(req.FinalUrl ?? req.Url); req.SameOrigin = fu.Scheme == MainFinalUri.Scheme && fu.Host == MainFinalUri.Host && fu.Port == MainFinalUri.Port; } } catch { }
                        Requests.Add(req);
                        _requestIdByUrl.TryAdd(req.Url, req.Id);
                        if (!string.IsNullOrWhiteSpace(req.FinalUrl)) _requestIdByUrl.TryAdd(req.FinalUrl, req.Id);
                        AddAdjacency(req.ParentId, req.Id);
                        if (!Hosts.TryGetValue(req.Host, out var h))
                        {
                            h = new StaticHost { Host = req.Host, RegistrableDomain = GetRegistrableDomain?.Invoke(req.Host) };
                            Hosts[req.Host] = h;
                        }
                        if (h.GroupId == 0) h.GroupId = System.Threading.Interlocked.Increment(ref _hostGroupSeed);
                        h.RequestCount++;
                        req.HostGroupId = h.GroupId;
                        try
                        {
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
                        } catch { }
                    }
                    // If HTML and we can go deeper, fetch small body for anchors
                    if (depth < maxDepth)
                    {
                        try
                        {
                            using var get = await http.GetAsync(u, HttpCompletionOption.ResponseHeadersRead, ct);
                            if (get.Content?.Headers?.ContentType?.MediaType != null && get.Content.Headers.ContentType.MediaType.IndexOf("text/html", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                using var stream = await get.Content.ReadAsStreamAsync();
                                using var ms = new System.IO.MemoryStream();
                                var buf = new byte[32 * 1024]; int read; int total = 0; const int capBytes = 128 * 1024;
                                while ((read = await stream.ReadAsync(buf, 0, buf.Length, ct)) > 0 && total < capBytes) { ms.Write(buf, 0, read); total += read; }
                                var html = System.Text.Encoding.UTF8.GetString(ms.ToArray());
                                foreach (System.Text.RegularExpressions.Match m2 in _anchorHrefRegex.Matches(html))
                                {
                                    var vv = m2.Groups[1].Success ? m2.Groups[1].Value : m2.Groups[2].Value;
                                    if (string.IsNullOrWhiteSpace(vv)) continue;
                                    Uri abs2; try { abs2 = new Uri(u, vv); } catch { continue; }
                                    if (abs2.Scheme != Uri.UriSchemeHttp && abs2.Scheme != Uri.UriSchemeHttps) continue;
                                    if (RespectRobots && robots != null) { var p2 = abs2.AbsolutePath; if (!robots.IsAllowed(p2)) continue; }
                                    if (LinkFirstPartyOnly)
                                    {
                                        try
                                        {
                                            var b = PrimaryRegistrableDomain ?? baseUri.Host;
                                            var d = GetRegistrableDomain?.Invoke(abs2.Host) ?? abs2.Host;
                                            if (!string.Equals(b, d, StringComparison.OrdinalIgnoreCase)) continue;
                                        } catch { }
                                    }
                                    lock (_sync)
                                    {
                                        if (seen.Count < maxPages && seen.Add(abs2.AbsoluteUri)) q.Enqueue((abs2, depth + 1, u.AbsoluteUri));
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
                finally
                {
                    try { gate.Release(); } catch { }
                }
            }, ct));
        }
        await Task.WhenAll(tasks);
    }
}
