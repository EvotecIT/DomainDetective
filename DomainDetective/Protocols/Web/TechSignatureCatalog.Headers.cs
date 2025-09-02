using System.Net.Http;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Header and cookie rules for technology detection (compiled).
/// </summary>
internal static partial class TechSignatureCatalog
{
    private static readonly (string header, string contains, string tech)[] HeaderRules = new[]
    {
        ("X-Powered-By","PHP","PHP"),
        ("X-Powered-By","ASP.NET Core","ASP.NET Core"),
        ("X-Powered-By","ASP.NET","ASP.NET"),
        ("X-AspNet-Version","","ASP.NET"),
        ("X-AspNetMvc-Version","","ASP.NET"),
        ("X-Powered-By","Express","Express"),
        ("X-Powered-By","Laravel","Laravel"),
        ("X-Powered-By","Django","Django"),
        // Common web server identifiers in Server header
        ("Server","Apache","Apache HTTP Server"),
        ("Server","nginx","nginx"),
        ("Server","Microsoft-IIS","IIS"),
        ("X-Shopify-Stage","","Shopify"),
        ("X-ShopId","","Shopify"),
        ("X-Magento-Cache-Debug","","Magento"),
        ("X-Magento-Vary","","Magento"),
        ("X-Amz-Cf-Id","","CloudFront"),
        ("X-Amz-Cf-Pop","","CloudFront"),
        ("X-Fastly-Request-ID","","Fastly"),
        ("X-Fastly-Debug","","Fastly"),
        ("X-Azure-OriginShield","","Azure CDN"),
        ("X-Azure-Ref","","Azure CDN"),
        ("X-Azure-FDID","","Azure Front Door"),
        ("Server","AzureFrontDoor","Azure Front Door"),
        ("X-Vercel-Id","","Vercel"),
        ("X-Vercel-Cache","","Vercel"),
        ("Server","Vercel","Vercel"),
        ("X-NF-Request-ID","","Netlify"),
        ("Server","Netlify","Netlify"),
        ("Server","Google Frontend","Google Frontend"),
        // CDN/Security proxies
        ("CF-RAY","","Cloudflare"),
        ("CF-Cache-Status","","Cloudflare"),
        ("Server","cloudflare","Cloudflare"),
        ("Server","AkamaiGHost","Akamai"),
        ("X-Akamai-Staging","","Akamai"),
        ("X-True-Cache-Key","","Akamai"),
        ("X-CDN","Incapsula","Imperva"),
        ("X-Iinfo","","Imperva"),
        // Fastly additional signals
        ("X-Timer","","Fastly"),
        ("X-Cache-Hits","","Fastly"),
        ("Fastly-Restarts","","Fastly"),
        ("Surrogate-Key","","Fastly"),
        ("Surrogate-Control","","Fastly"),
        ("X-Generator","","X-Generator") // handled specially to record value
    };

    private static readonly (string contains, string tech)[] CookieRules = new[]
    {
        ("PHPSESSID","PHP"),
        ("laravel_session","Laravel"),
        ("ASPXAUTH","ASP.NET"),
        ("ASP.NET_SessionId","ASP.NET"),
        ("wordpress_","WordPress"),
        ("wp-settings","WordPress"),
        ("woocommerce","WooCommerce"),
        ("_shopify","Shopify"),
        ("SHOP_SESSION_TOKEN","BigCommerce"),
        ("PrestaShop-","PrestaShop"),
        // Security/CDN cookies
        ("__cf_bm","Cloudflare"),
        ("cf_clearance","Cloudflare"),
        ("ak_bmsc","Akamai Bot Manager"),
        ("bm_sv","Akamai Bot Manager"),
        ("bm_sz","Akamai Bot Manager"),
        ("abck","Akamai Bot Manager"),
        ("visid_incap","Imperva"),
        ("incap_ses","Imperva"),
        ("nlbi_","Imperva"),
        ("XSRF-TOKEN","Angular")
    };
    /// <summary>
    /// Applies header and cookie compiled rules to infer technologies and record details.
    /// </summary>
    internal static void ApplyHeaderCookieRules(HttpResponseMessage resp, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        // Headers
        foreach (var (header, contains, tech) in HeaderRules)
        {
            if (header.Equals("X-Generator", System.StringComparison.OrdinalIgnoreCase))
            {
                // X-Generator recorded as tech value if present
                if (resp.Headers.TryGetValues(header, out var genVals) || resp.Content.Headers.TryGetValues(header, out genVals))
                {
                    foreach (var v in genVals)
                    {
                        var name = (v ?? string.Empty).Trim(); if (name.Length == 0) continue;
                        var nm = name.Split(' ')[0];
                        outTech.Add(nm);
                        details?.Add(new TechDetectionDetail { Name = nm, SourceKind = TechEvidenceKind.Header, Category = GetCategory(nm), Evidence = $"{header}: {v}", Confidence = 100 });
                    }
                }
                continue;
            }
            if (resp.Headers.TryGetValues(header, out var vals) || resp.Content.Headers.TryGetValues(header, out vals))
            {
                foreach (var v in vals)
                {
                    if (string.IsNullOrEmpty(contains))
                    {
                        if (!string.IsNullOrEmpty(v)) {
                            // Special-case X-Cache: detect patterns like "Hit from cloudfront"/"Miss from cloudfront"
                            if (header.Equals("X-Cache", System.StringComparison.OrdinalIgnoreCase)) {
                                var vv = (v ?? string.Empty);
                                if (vv.IndexOf(" from cloudfront", System.StringComparison.OrdinalIgnoreCase) >= 0) {
                                    outTech.Add("CloudFront");
                                    details?.Add(new TechDetectionDetail { Name = "CloudFront", SourceKind = TechEvidenceKind.Header, Category = GetCategory("CloudFront"), Evidence = $"{header}: {v}", Confidence = 95 });
                                }
                                continue; // do not treat generic X-Cache as evidence for any other tech here
                            }
                            outTech.Add(tech);
                            int conf = 90;
                            if (header.Equals("X-Served-By", System.StringComparison.OrdinalIgnoreCase)) conf = 80; // ambiguous
                            if (header.Equals("X-Cache-Hits", System.StringComparison.OrdinalIgnoreCase)) conf = 85; // supportive but not unique
                            if (header.Equals("Surrogate-Key", System.StringComparison.OrdinalIgnoreCase)) conf = 85; // Fastly feature but can be proxied
                            if (header.Equals("Surrogate-Control", System.StringComparison.OrdinalIgnoreCase)) conf = 85;
                            if (header.Equals("Fastly-Restarts", System.StringComparison.OrdinalIgnoreCase)) conf = 85;
                            details?.Add(new TechDetectionDetail { Name = tech, SourceKind = TechEvidenceKind.Header, Category = GetCategory(tech), Evidence = $"{header}: {v}", Confidence = conf });
                        }
                    }
                    else if (!string.IsNullOrEmpty(v) && v.IndexOf(contains, System.StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        outTech.Add(tech);
                        string? version = null;
                        try
                        {
                            // Basic version extraction for common headers
                            if (header.Equals("X-Powered-By", System.StringComparison.OrdinalIgnoreCase))
                            {
                                var m = Regex.Match(v ?? string.Empty, "(?i)(?:^|\b)php/?([\\d.]{1,250})");
                                if (m.Success) version = m.Groups[1].Value;
                            }
                            else if (header.Equals("X-AspNet-Version", System.StringComparison.OrdinalIgnoreCase) || header.Equals("X-AspNetMvc-Version", System.StringComparison.OrdinalIgnoreCase))
                            {
                                var m = Regex.Match(v ?? string.Empty, "([\\d.]{1,250})");
                                if (m.Success) version = m.Groups[1].Value;
                            }
                            else if (header.Equals("Server", System.StringComparison.OrdinalIgnoreCase))
                            {
                                var m = Regex.Match(v ?? string.Empty, "(?i)(?:Apache|nginx|Microsoft-IIS)/([\\d.]{1,250})");
                                if (m.Success) version = m.Groups[1].Value;
                            }
                        } catch { }
                        details?.Add(new TechDetectionDetail { Name = tech, Version = version, SourceKind = TechEvidenceKind.Header, Category = GetCategory(tech), Evidence = $"{header}: {v}", Confidence = 100 });
                    }
                }
            }
        }
        // Cookies
        if (resp.Headers.TryGetValues("Set-Cookie", out var cookies))
        {
            foreach (var c in cookies)
            {
                foreach (var (needle, tech) in CookieRules)
                {
                    if (!string.IsNullOrEmpty(c) && c.IndexOf(needle, System.StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        outTech.Add(tech);
                        details?.Add(new TechDetectionDetail { Name = tech, SourceKind = TechEvidenceKind.Cookie, Category = GetCategory(tech), Evidence = c.Length > 120 ? c.Substring(0,120) + "..." : c, Confidence = 85 });
                    }
                }
            }
        }
    }
}
