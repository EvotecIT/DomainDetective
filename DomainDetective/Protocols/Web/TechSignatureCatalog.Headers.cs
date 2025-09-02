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
        ("X-Powered-By","Express","Express"),
        ("X-Powered-By","Laravel","Laravel"),
        ("X-Powered-By","Django","Django"),
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
        ("woocommerce","WordPress"),
        ("_shopify","Shopify"),
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
                        outTech.Add(name.Split(' ')[0]);
                        details?.Add(new TechDetectionDetail { Name = name.Split(' ')[0], Source = "Header", Evidence = $"{header}: {v}", Confidence = 100 });
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
                        if (!string.IsNullOrEmpty(v)) { outTech.Add(tech); details?.Add(new TechDetectionDetail { Name = tech, Source = "Header", Evidence = $"{header}: {v}", Confidence = 90 }); }
                    }
                    else if (!string.IsNullOrEmpty(v) && v.IndexOf(contains, System.StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        outTech.Add(tech);
                        details?.Add(new TechDetectionDetail { Name = tech, Source = "Header", Evidence = $"{header}: {v}", Confidence = 100 });
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
                        details?.Add(new TechDetectionDetail { Name = tech, Source = "Cookie", Evidence = c.Length > 120 ? c.Substring(0,120) + "..." : c, Confidence = 90 });
                    }
                }
            }
        }
    }
}
