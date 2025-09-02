using System;

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
                        if (!string.IsNullOrWhiteSpace(pop)) host.EdgePop ??= pop;
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
                    lock (host) { host.EdgeProvider ??= "CloudFront"; host.EdgePop ??= first; }
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
}
