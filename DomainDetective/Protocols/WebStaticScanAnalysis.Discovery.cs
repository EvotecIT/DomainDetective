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
    private async Task<(List<string> schedule, HashSet<string> seen)> DiscoverResourcesAndBuildSchedule(Uri baseUri, string? body, HttpClient http, CancellationToken cancellationToken)
    {
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
        return (schedule, seen);
    }

    private async Task<(ConcurrentBag<string> cssCandidates, ConcurrentDictionary<string, int> hostCounts)> FetchResourceHeadersAsync(List<string> schedule, HttpClient http, CancellationToken cancellationToken)
    {
        var cssCandidates = new ConcurrentBag<string>();
        var hostCounts = new ConcurrentDictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int cap = Math.Max(1, (DiscoveryConcurrency > 0 ? DiscoveryConcurrency : Concurrency));
        using var gate = new SemaphoreSlim(cap);
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
        return (cssCandidates, hostCounts);
    }
}
