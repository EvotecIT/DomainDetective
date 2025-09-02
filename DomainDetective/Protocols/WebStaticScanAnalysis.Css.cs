using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// CSS processing for additional resource discovery in WebStaticScanAnalysis.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private async Task ProcessCssAsync(ConcurrentBag<string> cssCandidates, HashSet<string> seen, ConcurrentDictionary<string, int> hostCounts, HttpClient http, CancellationToken cancellationToken)
    {
        const int MaxCssBytes = 128 * 1024;
        var list = cssCandidates.Distinct(System.StringComparer.OrdinalIgnoreCase).ToArray();
        int cap = Math.Max(1, (CssConcurrency > 0 ? CssConcurrency : Concurrency));
        using var gate = new SemaphoreSlim(cap);
        var tasks = new List<Task>(list.Length);
        foreach (var css in list)
        {
            await gate.WaitAsync(cancellationToken);
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    using var response = await http.GetAsync(css, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    if (response.Headers.TryGetValues("Set-Cookie", out var _)) System.Threading.Interlocked.Increment(ref _cookiesSet);
                    try { lock (_sync) { var chost = new Uri(css).Host; if (Hosts.TryGetValue(chost, out var hh)) CaptureEdgeHints(response, hh); } } catch { }
                    using var stream = await response.Content.ReadAsStreamAsync();
                    using var limited = new System.IO.MemoryStream();
                    var buffer = new byte[16 * 1024];
                    int read; int total = 0;
                    while ((read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0 && total < MaxCssBytes)
                    {
                        limited.Write(buffer, 0, read);
                        total += read;
                    }
                    var text = Encoding.UTF8.GetString(limited.ToArray());
                    foreach (Match m in _cssUrlRegex.Matches(text))
                    {
                        var v = m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value;
                        var val = (v ?? string.Empty).Trim().Trim('\'', '"');
                        if (string.IsNullOrWhiteSpace(val)) continue;
                        if (val.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) continue;
                        try
                        {
                            var abs = new Uri(new Uri(css), val);
                            // First-party only filtering
                            if (SkipThirdParty)
                            {
                                try
                                {
                                    var baseDom = PrimaryRegistrableDomain ?? new Uri(css).Host;
                                    var hostDom = GetRegistrableDomain?.Invoke(abs.Host) ?? abs.Host;
                                    if (!string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase)) return;
                                }
                                catch { }
                            }
                            bool add;
                            lock (_sync) { add = seen.Add(abs.AbsoluteUri); }
                            if ((abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps) && add && Requests.Count < MaxResources)
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
                            // First-party only filtering
                            if (SkipThirdParty)
                            {
                                try
                                {
                                    var baseDom = PrimaryRegistrableDomain ?? new Uri(css).Host;
                                    var hostDom = GetRegistrableDomain?.Invoke(abs.Host) ?? abs.Host;
                                    if (!string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase)) return;
                                }
                                catch { }
                            }
                            bool add;
                            lock (_sync) { add = seen.Add(abs.AbsoluteUri); }
                            if ((abs.Scheme == Uri.UriSchemeHttp || abs.Scheme == Uri.UriSchemeHttps) && add && Requests.Count < MaxResources)
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
                                lock (_sync)
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
                        catch { }
                    }
                }
                catch { }
                finally { try { gate.Release(); } catch { } }
            }, cancellationToken));
        }
        await Task.WhenAll(tasks);
    }
}
