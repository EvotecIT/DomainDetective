using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Precompiled, typed technology detection rules to avoid JSON escaping and duplication.
/// Provides helpers to apply header/cookie/meta, path/domain, and body rules.
/// </summary>
/// <summary>
/// Partial static class containing compiled signature sets and helpers. Split across files by rule category
/// (Headers/Cookies, Paths/Domains, Body) to keep maintenance manageable as the catalog grows.
/// </summary>
internal static partial class TechSignatureCatalog
{
    internal static TechCategory GetCategory(string tech)
    {
        var t = tech ?? string.Empty;
        if (t.Equals("Apache", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Apache HTTP Server", System.StringComparison.OrdinalIgnoreCase) || t.Equals("nginx", System.StringComparison.OrdinalIgnoreCase) || t.Equals("IIS", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.WebServer;
        if (t.Equals("WordPress", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Magento", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.CMS;
        if (t.Equals("Shopify", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.ECommerce;
        if (t.Equals("React", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Angular", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Vue", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Next.js", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Nuxt.js", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.JSFramework;
        if (t.Equals("jQuery", System.StringComparison.OrdinalIgnoreCase) || t.Equals("jQuery Migrate", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Bootstrap", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Swiper", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.JSLibrary;
        if (t.Equals("ASP.NET", System.StringComparison.OrdinalIgnoreCase) || t.Equals("ASP.NET Core", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Express", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Laravel", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Django", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Framework;
        if (t.Equals("PHP", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Language;
        if (t.Equals("Google Analytics", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Analytics;
        if (t.Equals("Google Tag Manager", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.TagManager;
        if (t.Equals("Cloudflare Browser Insights", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Cloudflare", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.CDN;
        if (t.Equals("Akamai", System.StringComparison.OrdinalIgnoreCase) || t.Equals("CloudFront", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Fastly", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Azure CDN", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Azure Front Door", System.StringComparison.OrdinalIgnoreCase) || t.Equals("jsDelivr CDN", System.StringComparison.OrdinalIgnoreCase) || t.Equals("StackPath", System.StringComparison.OrdinalIgnoreCase) || t.Equals("CDN77", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.CDN;
        if (t.Equals("Akamai Bot Manager", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Security;
        if (t.Equals("Imperva", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Security;
        if (t.Equals("Atlassian Statuspage", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.IssueTracker;
        if (t.Equals("Google Font API", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Fonts;
        if (t.Equals("reCAPTCHA", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Security;
        if (t.Equals("Vercel", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Netlify", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Heroku", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Azure App Service", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Google App Engine", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Firebase Hosting", System.StringComparison.OrdinalIgnoreCase) || t.Equals("Google Frontend", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.PaaS;
        if (t.EndsWith("Site Verification", System.StringComparison.OrdinalIgnoreCase) || t.EndsWith("Domain Verification", System.StringComparison.OrdinalIgnoreCase)) return TechCategory.Verification;
        return TechCategory.Other;
    }
    /// <summary>
    /// Applies built-in header, cookie, and meta rules to infer technologies.
    /// </summary>
    /// <param name="resp">HTTP response (HEAD or GET) used for headers and cookies.</param>
    /// <param name="body">Optional HTML body snapshot to search for meta generator hints.</param>
    /// <param name="outTech">Set to append inferred technologies.</param>
    /// <param name="details">Optional list to collect detection details.</param>
    public static void ApplyHeadersCookiesMeta(HttpResponseMessage resp, string? body, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        try
        {
            ApplyHeaderCookieRules(resp, outTech, details);
            if (!string.IsNullOrWhiteSpace(body)) { ApplyMetaGeneratorRules(body!, outTech, details); ApplyMetaVerificationRules(body!, outTech, details); ApplyBodyRules(body!, outTech, details); }
        } catch { }
    }

    internal static void ApplyMetaGeneratorRules(string body, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        try
        {
            var m = System.Text.RegularExpressions.Regex.Match(body, "<meta[^>]*name=\\\"generator\\\"[^>]*content=\\\"([^\\\"]+)\\\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success)
            {
                var val = (m.Groups[1].Value ?? string.Empty).Trim();
                if (!string.IsNullOrWhiteSpace(val))
                {
                    string name;
                    var low = val.ToLowerInvariant();
                    if (low.Contains("wordpress")) name = "WordPress";
                    else if (low.Contains("joomla")) name = "Joomla";
                    else if (low.Contains("drupal")) name = "Drupal";
                    else if (low.Contains("prestashop")) name = "PrestaShop";
                    else if (low.Contains("shopify")) name = "Shopify";
                    else if (low.Contains("magento")) name = "Magento";
                    else if (low.Contains("squarespace")) name = "Squarespace";
                    else if (low.Contains("wix")) name = "Wix";
                    else if (low.Contains("opencart")) name = "OpenCart";
                    else if (low.Contains("blogger")) name = "Blogger";
                    else if (low.Contains("ghost")) name = "Ghost";
                    else if (low.Contains("hugo")) name = "Hugo";
                    else if (low.Contains("jekyll")) name = "Jekyll";
                    else name = val.Split(' ')[0];
                    string? version = null;
                    var vm = System.Text.RegularExpressions.Regex.Match(val, "([\\d]+(?:[.][\\d]+)+)");
                    if (vm.Success) version = vm.Groups[1].Value;
                    outTech.Add(name);
                    details?.Add(new TechDetectionDetail { Name = name, Version = version, SourceKind = TechEvidenceKind.Meta, Category = GetCategory(name), Evidence = val, Confidence = 100 });
                }
            }
        } catch { }
    }

    internal static void ApplyMetaVerificationRules(string body, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        try
        {
            // Common verification meta names
            var names = new (string metaName, string tech)[]
            {
                ("google-site-verification","Google Site Verification"),
                ("facebook-domain-verification","Facebook Domain Verification"),
                ("apple-domain-verification","Apple Domain Verification"),
                ("msvalidate.01","Bing Site Verification"),
                ("yandex-verification","Yandex Site Verification"),
                ("pinterest-site-verification","Pinterest Site Verification"),
                ("ahrefs-site-verification","Ahrefs Site Verification"),
            };
            foreach (var (metaName, tech) in names)
            {
                var pattern = $"<meta[^>]*name=\\\"{System.Text.RegularExpressions.Regex.Escape(metaName)}\\\"[^>]*content=\\\"([^\\\"]+)\\\"";
                var m = System.Text.RegularExpressions.Regex.Match(body, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                if (m.Success)
                {
                    outTech.Add(tech);
                    var val = m.Groups[1].Value;
                    details?.Add(new TechDetectionDetail { Name = tech, SourceKind = TechEvidenceKind.Meta, Category = GetCategory(tech), Evidence = $"{metaName}={val}", Confidence = 100 });
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Applies built-in path, domain suffix, and body regex rules to infer technologies.
    /// </summary>
    /// <param name="requests">Captured static requests (URLs) for path-based matching.</param>
    /// <param name="hosts">Aggregated host entries for domain suffix checks.</param>
    /// <param name="body">Optional HTML body snapshot for regex rules.</param>
    /// <param name="getRegistrableDomain">Public Suffix List resolver for registrable domains.</param>
    /// <param name="outTech">Set to append inferred technologies.</param>
    /// <param name="details">Optional list to collect detection details.</param>
    public static void ApplyPathsDomainsBody(
        IEnumerable<WebStaticScanAnalysis.StaticRequest> requests,
        IDictionary<string, WebStaticScanAnalysis.StaticHost> hosts,
        string? body,
        Func<string,string>? getRegistrableDomain,
        System.Collections.Generic.ISet<string> outTech,
        System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        try
        {
            ApplyPathDomainRules(requests, hosts, getRegistrableDomain, outTech, details);
            if (!string.IsNullOrWhiteSpace(body)) ApplyBodyRules(body!, outTech, details);
        } catch { }
    }
}
