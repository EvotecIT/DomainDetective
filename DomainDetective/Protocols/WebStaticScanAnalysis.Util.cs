using System;
using System.Linq;

namespace DomainDetective;

/// <summary>
/// Utility helpers for the web static scan split into a separate partial for readability.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private static string Categorize(string url, string? contentType)
    {
        string type = (contentType ?? string.Empty).ToLowerInvariant();
        if (type.StartsWith("image/")) return "image";
        if (type.Contains("javascript") || type == "application/x-javascript") return "script";
        if (type == "text/css") return "stylesheet";
        if (type.StartsWith("font/") || type.Contains("woff") || type.Contains("truetype")) return "font";
        if (type.StartsWith("text/html") || type.StartsWith("application/xhtml")) return "document";
        if (type.Contains("json")) return "json";
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

    private static void FillResponseMeta(StaticRequest req, System.Net.Http.HttpResponseMessage resp)
    {
        try
        {
            var ver = resp?.Version;
            if (ver != null) { req.ProtocolVersion = ver.ToString(); }
#if NET6_0_OR_GREATER
            if (ver != null)
            {
                req.Http3 = ver >= System.Net.Http.HttpVersion.Version30;
                req.Http2 = ver >= System.Net.Http.HttpVersion.Version20;
            }
#else
            if (ver != null)
            {
                req.Http2 = ver.Major >= 2;
                req.Http3 = false;
            }
#endif
            string JoinVals(System.Net.Http.Headers.HttpHeaders h, string name)
            {
                return h.TryGetValues(name, out var vals) ? string.Join(",", vals) : null;
            }
            req.CacheControl = JoinVals(resp.Headers, "Cache-Control") ?? JoinVals(resp.Content?.Headers, "Cache-Control");
            req.ETag = resp.Headers?.ETag != null ? resp.Headers.ETag.Tag : (JoinVals(resp.Headers, "ETag") ?? JoinVals(resp.Content?.Headers, "ETag"));
            req.LastModified = resp.Content?.Headers?.LastModified?.ToString() ?? JoinVals(resp.Headers, "Last-Modified") ?? JoinVals(resp.Content?.Headers, "Last-Modified");
            var ageStr = JoinVals(resp.Headers, "Age") ?? JoinVals(resp.Content?.Headers, "Age");
            if (int.TryParse((ageStr ?? string.Empty).Trim(), out var ageVal)) req.Age = ageVal; else req.Age = null;
            req.Vary = JoinVals(resp.Headers, "Vary") ?? JoinVals(resp.Content?.Headers, "Vary");
            req.Expires = resp.Content?.Headers?.Expires?.ToString() ?? JoinVals(resp.Headers, "Expires") ?? JoinVals(resp.Content?.Headers, "Expires");
        }
        catch { }
    }
    private static ResourceCategory ToCategoryKind(string? category)
    {
        switch ((category ?? string.Empty).ToLowerInvariant())
        {
            case "document": return ResourceCategory.Document;
            case "stylesheet": return ResourceCategory.Stylesheet;
            case "script": return ResourceCategory.Script;
            case "image": return ResourceCategory.Image;
            case "font": return ResourceCategory.Font;
            case "json": return ResourceCategory.Json;
            default: return ResourceCategory.Other;
        }
    }

    private static MediaSupertype ToMediaSupertype(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType)) return MediaSupertype.Unknown;
        var ct = contentType.Trim();
        var slash = ct.IndexOf('/');
        var major = slash > 0 ? ct.Substring(0, slash) : ct;
        return major.ToLowerInvariant() switch
        {
            "text" => MediaSupertype.Text,
            "image" => MediaSupertype.Image,
            "audio" => MediaSupertype.Audio,
            "video" => MediaSupertype.Video,
            "application" => MediaSupertype.Application,
            "multipart" => MediaSupertype.Multipart,
            _ => MediaSupertype.Unknown
        };
    }

    private static StatusClass ToStatusClass(int statusCode)
    {
        if (statusCode <= 0) return StatusClass.None;
        var cls = statusCode / 100;
        return cls switch
        {
            1 => StatusClass.Informational,
            2 => StatusClass.Success,
            3 => StatusClass.Redirection,
            4 => StatusClass.ClientError,
            5 => StatusClass.ServerError,
            _ => StatusClass.None
        };
    }

    private static string CategoryKey(ResourceCategory kind)
    {
        return kind switch
        {
            ResourceCategory.Document => "document",
            ResourceCategory.Stylesheet => "stylesheet",
            ResourceCategory.Script => "script",
            ResourceCategory.Image => "image",
            ResourceCategory.Font => "font",
            ResourceCategory.Json => "json",
            _ => "other"
        };
    }

    private void EnsureTechDetailsForAllDetections(string? body, HttpAnalysis? main)
    {
        try
        {
            var existing = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var d in TechDetails) existing.Add(d.Name);
            foreach (var name in TechDetections)
            {
                if (existing.Contains(name)) continue;
                // Try to locate plausible evidence by name
                string? evidence = null; TechEvidenceKind kind = TechEvidenceKind.Heuristic; int conf = 60;
                var lower = name.ToLowerInvariant();
                if (lower == "cloudflare")
                {
                    var server = main?.ServerHeader ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(server) && server.IndexOf("cloudflare", System.StringComparison.OrdinalIgnoreCase) >= 0)
                    { evidence = "Server: " + server; kind = TechEvidenceKind.Header; conf = 75; }
                    else if (Hosts.Values.Any(h => string.Equals(h.EdgeProvider, "Cloudflare", System.StringComparison.OrdinalIgnoreCase)))
                    { evidence = "EdgeProvider=Cloudflare"; kind = TechEvidenceKind.Heuristic; conf = 75; }
                }
                else if (lower == "wordpress")
                {
                    var hit = Requests.Select(r => { try { return new System.Uri(r.FinalUrl ?? r.Url).AbsolutePath; } catch { return null; } })
                        .FirstOrDefault(p => p != null && (p.Contains("/wp-content/") || p.Contains("/wp-includes/")));
                    if (!string.IsNullOrWhiteSpace(hit)) { evidence = hit!; kind = TechEvidenceKind.Path; conf = 75; }
                    else if (!string.IsNullOrWhiteSpace(body) && System.Text.RegularExpressions.Regex.IsMatch(body, "(?i)name=\"generator\"[^>]*wordpress"))
                    { evidence = "meta generator contains WordPress"; kind = TechEvidenceKind.Meta; conf = 75; }
                }
                else if (lower == "jquery")
                {
                    var hit = Requests.Select(r => { try { return new System.Uri(r.FinalUrl ?? r.Url).AbsolutePath; } catch { return null; } })
                        .FirstOrDefault(p => p != null && p.IndexOf("jquery", System.StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!string.IsNullOrWhiteSpace(hit)) { evidence = hit!; kind = TechEvidenceKind.Path; conf = 70; }
                }
                else if (lower == "jquery migrate" || lower == "jquery migrate".Replace(" ", string.Empty))
                {
                    var hit = Requests.Select(r => { try { return new System.Uri(r.FinalUrl ?? r.Url).AbsolutePath; } catch { return null; } })
                        .FirstOrDefault(p => p != null && p.IndexOf("jquery-migrate", System.StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!string.IsNullOrWhiteSpace(hit)) { evidence = hit!; kind = TechEvidenceKind.Path; conf = 70; }
                }
                else if (lower == "amp")
                {
                    if (!string.IsNullOrWhiteSpace(body) && System.Text.RegularExpressions.Regex.IsMatch(body, "(?i)<link[^>]*rel=\"amphtml\""))
                    { evidence = "link rel=amphtml"; kind = TechEvidenceKind.Body; conf = 80; }
                }
                else if (lower == "google font api")
                {
                    var hit = Requests.Select(r => { try { return new System.Uri(r.FinalUrl ?? r.Url).Host; } catch { return null; } })
                        .FirstOrDefault(h => h != null && (h.EndsWith("fonts.googleapis.com", System.StringComparison.OrdinalIgnoreCase) || h.EndsWith("fonts.google.com", System.StringComparison.OrdinalIgnoreCase)));
                    if (!string.IsNullOrWhiteSpace(hit)) { evidence = hit!; kind = TechEvidenceKind.DomainSuffix; conf = 75; }
                }

                if (string.IsNullOrWhiteSpace(evidence)) { evidence = "fallback (summary attribution)"; kind = TechEvidenceKind.Heuristic; conf = 50; }
                TechDetails.Add(new TechDetectionDetail
                {
                    Name = name,
                    SourceKind = kind,
                    Category = TechSignatureCatalog.GetCategory(name),
                    Evidence = evidence,
                    Confidence = conf
                });
                existing.Add(name);
            }
        }
        catch { }
    }

    private void RecordCookies(string host, System.Net.Http.HttpResponseMessage resp)
    {
        try
        {
            if (!resp.Headers.TryGetValues("Set-Cookie", out var setCookies)) return;
            var baseDom = PrimaryRegistrableDomain ?? string.Empty;
            var hostDom = GetRegistrableDomain?.Invoke(host) ?? host;
            var isFirstParty = !string.IsNullOrWhiteSpace(baseDom) && string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase);
            if (!isFirstParty) return;
            foreach (var sc in setCookies)
            {
                // Simple parser: split by ';', first segment is name=value
                bool secure = false, httpOnly = false, ssAny = false;
                bool ssLax = false, ssStrict = false, ssNone = false;
                bool maxAge = false, domain = false;
                var parts = (sc ?? string.Empty).Split(';');
                for (int i = 1; i < parts.Length; i++)
                {
                    var seg = parts[i].Trim(); if (seg.Length == 0) continue;
                    var eq = seg.IndexOf('=');
                    var key = eq > 0 ? seg.Substring(0, eq) : seg;
                    var val = eq > 0 ? seg.Substring(eq + 1) : string.Empty;
                    if (key.Equals("Secure", StringComparison.OrdinalIgnoreCase)) secure = true;
                    else if (key.Equals("HttpOnly", StringComparison.OrdinalIgnoreCase)) httpOnly = true;
                    else if (key.Equals("SameSite", StringComparison.OrdinalIgnoreCase))
                    {
                        ssAny = true;
                        var v = (val ?? string.Empty).Trim();
                        if (v.Equals("Lax", StringComparison.OrdinalIgnoreCase)) ssLax = true;
                        else if (v.Equals("Strict", StringComparison.OrdinalIgnoreCase)) ssStrict = true;
                        else if (v.Equals("None", StringComparison.OrdinalIgnoreCase)) ssNone = true;
                    }
                    else if (key.Equals("Max-Age", StringComparison.OrdinalIgnoreCase)) maxAge = true;
                    else if (key.Equals("Domain", StringComparison.OrdinalIgnoreCase)) domain = true;
                }
                lock (_sync)
                {
                    CookieSummary.TotalFirstParty++;
                    if (secure) CookieSummary.Secure++;
                    if (httpOnly) CookieSummary.HttpOnly++;
                    if (ssLax) CookieSummary.SameSiteLax++;
                    if (ssStrict) CookieSummary.SameSiteStrict++;
                    if (ssNone) CookieSummary.SameSiteNone++;
                    if (!ssAny) CookieSummary.SameSiteMissing++;
                    if (maxAge) CookieSummary.MaxAgePresent++;
                    if (domain) CookieSummary.DomainPresent++;
                }
            }
        }
        catch { }
    }

    private void RecordCorsHeaders(string host, System.Net.Http.HttpResponseMessage resp)
    {
        try
        {
            var baseDom = PrimaryRegistrableDomain ?? string.Empty;
            var hostDom = GetRegistrableDomain?.Invoke(host) ?? host;
            var isFirstParty = !string.IsNullOrWhiteSpace(baseDom) && string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase);
            if (!isFirstParty) return;
            string? origin = null, methods = null, headers = null, credentials = null;
            if (resp.Headers.TryGetValues("Access-Control-Allow-Origin", out var a)) origin = System.Linq.Enumerable.FirstOrDefault(a);
            if (resp.Headers.TryGetValues("Access-Control-Allow-Methods", out var m)) methods = System.Linq.Enumerable.FirstOrDefault(m);
            if (resp.Headers.TryGetValues("Access-Control-Allow-Headers", out var h)) headers = System.Linq.Enumerable.FirstOrDefault(h);
            if (resp.Headers.TryGetValues("Access-Control-Allow-Credentials", out var c)) credentials = System.Linq.Enumerable.FirstOrDefault(c);
            if (origin == null && methods == null && headers == null && credentials == null) return;
            lock (_sync)
            {
                Cors.FirstPartyResponses++;
                if (!string.IsNullOrWhiteSpace(origin))
                {
                    if (origin.Trim() == "*") { Cors.WildcardOriginCount++; if (Hosts.TryGetValue(host, out var hh)) hh.CorsAnyOrigin = true; }
                    else Cors.Origins.Add(origin.Trim());
                }
                if (!string.IsNullOrWhiteSpace(methods))
                {
                    foreach (var tok in methods.Split(','))
                    {
                        var t = tok.Trim(); if (t.Length > 0) Cors.Methods.Add(t);
                    }
                }
                if (!string.IsNullOrWhiteSpace(headers))
                {
                    foreach (var tok in headers.Split(','))
                    {
                        var t = tok.Trim(); if (t.Length > 0) Cors.Headers.Add(t);
                    }
                }
                if (!string.IsNullOrWhiteSpace(credentials) && credentials.Trim().Equals("true", StringComparison.OrdinalIgnoreCase)) Cors.CredentialsCount++;
            }
        }
        catch { }
    }

    private void RecordServerTiming(string host, System.Net.Http.HttpResponseMessage resp)
    {
        try
        {
            var baseDom = PrimaryRegistrableDomain ?? string.Empty;
            var hostDom = GetRegistrableDomain?.Invoke(host) ?? host;
            var isFirstParty = !string.IsNullOrWhiteSpace(baseDom) && string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase);
            if (!isFirstParty) return;
            if (!(resp.Headers.TryGetValues("Server-Timing", out var st) || resp.Content.Headers.TryGetValues("Server-Timing", out st))) return;
            lock (_sync) { ServerTiming.FirstPartyResponses++; }
            foreach (var header in st)
            {
                if (string.IsNullOrWhiteSpace(header)) continue;
                foreach (var entry in header.Split(','))
                {
                    var seg = entry.Trim(); if (seg.Length == 0) continue;
                    var semi = seg.IndexOf(';');
                    var metric = semi >= 0 ? seg.Substring(0, semi) : seg;
                    if (!string.IsNullOrWhiteSpace(metric)) lock (_sync) ServerTiming.Metrics.Add(metric.Trim());
                }
            }
        }
        catch { }
    }

    private void ParseLinkHintsFromBody(Uri baseUri, string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return;
        try
        {
            var re = new System.Text.RegularExpressions.Regex("(?is)<link[^>]*?rel=\\\"(preconnect|dns-prefetch|preload|prefetch)\\\"[^>]*?href=\\\"([^\\\"]+)\\\"[^>]*>");
            foreach (System.Text.RegularExpressions.Match m in re.Matches(body))
            {
                var rel = m.Groups[1].Value;
                var href = m.Groups[2].Value;
                if (string.IsNullOrWhiteSpace(href)) continue;
                try
                {
                    var abs = new Uri(baseUri, href);
                    var host = abs.Host;
                    var baseDom = PrimaryRegistrableDomain ?? baseUri.Host;
                    var hostDom = GetRegistrableDomain?.Invoke(host) ?? host;
                    var fp = string.Equals(baseDom, hostDom, StringComparison.OrdinalIgnoreCase);
                    lock (_sync)
                    {
                        LinkHints.Add(new LinkHint { Rel = rel, Href = abs.AbsoluteUri, Host = host, FirstParty = fp });
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ParseStructuredDataFromBody(string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) return;
        try
        {
            var re = new System.Text.RegularExpressions.Regex(@"(?is)<script[^>]*type=""application/ld\+json""[^>]*>(.*?)</script>");
            foreach (System.Text.RegularExpressions.Match m in re.Matches(body))
            {
                var json = m.Groups[1].Value;
                if (string.IsNullOrWhiteSpace(json)) continue;
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(json);
                    ExtractTypes(doc.RootElement);
                }
                catch { }
            }
        }
        catch { }

        void ExtractTypes(System.Text.Json.JsonElement el)
        {
            try
            {
                if (el.ValueKind == System.Text.Json.JsonValueKind.Object)
                {
                    foreach (var p in el.EnumerateObject())
                    {
                        if (p.NameEquals("@type"))
                        {
                            if (p.Value.ValueKind == System.Text.Json.JsonValueKind.String)
                            {
                                var t = p.Value.GetString(); if (!string.IsNullOrWhiteSpace(t)) lock (_sync) StructuredDataTypes[t!] = StructuredDataTypes.TryGetValue(t!, out var c) ? c + 1 : 1;
                            }
                            else if (p.Value.ValueKind == System.Text.Json.JsonValueKind.Array)
                            {
                                foreach (var item in p.Value.EnumerateArray()) if (item.ValueKind == System.Text.Json.JsonValueKind.String) { var t = item.GetString(); if (!string.IsNullOrWhiteSpace(t)) lock (_sync) StructuredDataTypes[t!] = StructuredDataTypes.TryGetValue(t!, out var c) ? c + 1 : 1; }
                            }
                        }
                        else
                        {
                            ExtractTypes(p.Value);
                        }
                    }
                }
                else if (el.ValueKind == System.Text.Json.JsonValueKind.Array)
                {
                    foreach (var item in el.EnumerateArray()) ExtractTypes(item);
                }
            }
            catch { }
        }
    }

    private void CaptureEdgeHints(System.Net.Http.HttpResponseMessage resp, StaticHost host)
    {
        try
        {
            // Cloudflare
            if ((resp.Headers.TryGetValues("CF-RAY", out var cfr) || resp.Content.Headers.TryGetValues("CF-RAY", out cfr)))
            {
                var first = System.Linq.Enumerable.FirstOrDefault(cfr);
                if (!string.IsNullOrWhiteSpace(first))
                {
                    var idx = first.LastIndexOf('-');
                    var pop = idx > 0 && idx + 1 < first.Length ? first.Substring(idx + 1) : null;
                    lock (host)
                    {
                        host.EdgeProvider ??= "Cloudflare";
                        if (!string.IsNullOrWhiteSpace(pop)) { host.EdgePop ??= pop; NormalizeEdgePopFields(host); }
                    }
                }
            }
            if ((resp.Headers.TryGetValues("CF-Cache-Status", out var cfcs) || resp.Content.Headers.TryGetValues("CF-Cache-Status", out cfcs)))
            {
                var first = System.Linq.Enumerable.FirstOrDefault(cfcs);
                if (!string.IsNullOrWhiteSpace(first))
                {
                    lock (host) { host.EdgeProvider ??= "Cloudflare"; host.EdgeCacheStatus ??= first.ToUpperInvariant(); }
                }
            }
            // AWS CloudFront
            if ((resp.Headers.TryGetValues("X-Amz-Cf-Pop", out var pops) || resp.Content.Headers.TryGetValues("X-Amz-Cf-Pop", out pops)))
            {
                var first = System.Linq.Enumerable.FirstOrDefault(pops);
                if (!string.IsNullOrWhiteSpace(first))
                {
                    lock (host) { host.EdgeProvider ??= "CloudFront"; host.EdgePop ??= first; NormalizeEdgePopFields(host); }
                }
            }
            if ((resp.Headers.TryGetValues("X-Cache", out var xcache) || resp.Content.Headers.TryGetValues("X-Cache", out xcache)))
            {
                var first = System.Linq.Enumerable.FirstOrDefault(xcache) ?? string.Empty;
                var idx = first.IndexOf(" from cloudfront", StringComparison.OrdinalIgnoreCase);
                if (idx > 0)
                {
                    var status = first.Substring(0, idx).Trim();
                    lock (host)
                    {
                        host.EdgeProvider ??= "CloudFront";
                        if (!string.IsNullOrWhiteSpace(status)) host.EdgeCacheStatus ??= status.ToUpperInvariant();
                    }
                }
            }
            // Fastly (no PoP parsing to avoid overreach)
            if (resp.Headers.Contains("X-Fastly-Request-ID") || resp.Headers.Contains("X-Timer") || resp.Headers.Contains("Surrogate-Control") || resp.Headers.Contains("Surrogate-Key"))
            {
                lock (host) { host.EdgeProvider ??= "Fastly"; }
            }
            // Fastly cache status if provider already recognized
            if (string.Equals(host.EdgeProvider, "Fastly", StringComparison.Ordinal))
            {
                if ((resp.Headers.TryGetValues("X-Cache", out var fastlyCache) || resp.Content.Headers.TryGetValues("X-Cache", out fastlyCache)))
                {
                    var first = System.Linq.Enumerable.FirstOrDefault(fastlyCache);
                    if (!string.IsNullOrWhiteSpace(first))
                    {
                        var parts = first.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var token = parts.Length > 0 ? parts[0] : null;
                        if (!string.IsNullOrWhiteSpace(token)) lock (host) host.EdgeCacheStatus ??= token.ToUpperInvariant();
                    }
                }
                if ((resp.Headers.TryGetValues("X-Cache-Hits", out var hits) || resp.Content.Headers.TryGetValues("X-Cache-Hits", out hits)))
                {
                    var first = System.Linq.Enumerable.FirstOrDefault(hits);
                    if (!string.IsNullOrWhiteSpace(first) && int.TryParse(first.Trim(), out var n))
                    {
                        lock (host) host.EdgeCacheStatus ??= $"HITS:{n}";
                    }
                }
            }
            // Akamai: provider + cache status parsing when headers indicate Akamai
            bool akamai = false;
            if (resp.Headers.TryGetValues("Server", out var srv) && System.Linq.Enumerable.Any(srv, v => (v ?? string.Empty).IndexOf("AkamaiGHost", StringComparison.OrdinalIgnoreCase) >= 0)) akamai = true;
            if (!akamai && (resp.Headers.Contains("X-Akamai-Staging") || resp.Headers.Contains("X-True-Cache-Key") || resp.Headers.Contains("X-Akamai-Session-Info"))) akamai = true;
            if (akamai)
            {
                lock (host) { host.EdgeProvider ??= "Akamai"; }
                if ((resp.Headers.TryGetValues("X-Cache", out var akCache) || resp.Content.Headers.TryGetValues("X-Cache", out akCache)))
                {
                    var first = System.Linq.Enumerable.FirstOrDefault(akCache) ?? string.Empty;
                    var parts = first.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    var token = parts.Length > 0 ? parts[0] : null;
                    if (!string.IsNullOrWhiteSpace(token) && token.StartsWith("TCP_", StringComparison.OrdinalIgnoreCase))
                    {
                        lock (host) host.EdgeCacheStatus ??= token.ToUpperInvariant();
                    }
                    else if (first.IndexOf("AkamaiGHost", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (!string.IsNullOrWhiteSpace(token)) lock (host) host.EdgeCacheStatus ??= token.ToUpperInvariant();
                    }
                }
            }
            // Google Frontend (App Engine / Cloud CDN)
            if (resp.Headers.TryGetValues("Server", out var gsv) && System.Linq.Enumerable.Any(gsv, v => (v ?? string.Empty).IndexOf("Google Frontend", StringComparison.OrdinalIgnoreCase) >= 0))
            {
                lock (host) { host.EdgeProvider ??= "Google Frontend"; }
            }
            // Azure Front Door
            if (resp.Headers.Contains("X-Azure-FDID") || (resp.Headers.TryGetValues("Server", out var sv) && System.Linq.Enumerable.Any(sv, v => (v ?? string.Empty).IndexOf("AzureFrontDoor", StringComparison.OrdinalIgnoreCase) >= 0)))
            {
                lock (host) { host.EdgeProvider ??= "Azure Front Door"; }
            }
        }
        catch { }
    }

    // PoP mapping and normalization moved to WebStaticScanAnalysis.Pops.cs
}
