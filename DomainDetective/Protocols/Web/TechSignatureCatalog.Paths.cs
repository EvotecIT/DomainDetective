using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Path and domain suffix rules for technology detection (compiled).
/// </summary>
internal static partial class TechSignatureCatalog
{
    private static readonly (Regex regex, string tech)[] PathRules = new[]
    {
        (new Regex("wp-(?:content|includes)/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "WordPress"),
        (new Regex("/wp-json/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "WordPress"),
        (new Regex("(?:^|/)sites/(?:all|default)/|/core/(?:misc|modules)/|misc/drupal\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Drupal"),
        (new Regex("(?:^|/)(?:media/system/js|templates/system|components/com_)", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Joomla"),
        // PrestaShop indicators
        (new Regex("(?:^|/)(?:themes/classic/assets/|modules/ps_[^/]+/|prestashop(?:\\.min)?\\.(?:js|css))", RegexOptions.IgnoreCase|RegexOptions.Compiled), "PrestaShop"),
        (new Regex("jquery.*\\.js(?:\\?ver(?:sion)?=([\\d.]+))?", RegexOptions.IgnoreCase|RegexOptions.Compiled), "jQuery"),
        (new Regex("jquery[\\.-]migrate(?:-([\\d.]+))?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?", RegexOptions.IgnoreCase|RegexOptions.Compiled), "jQuery Migrate"),
        (new Regex("_next/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Next.js"),
        (new Regex("_nuxt/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Nuxt.js"),
        (new Regex("/skin/frontend/|/static/frontend/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Magento"),
        (new Regex("react|react-dom", RegexOptions.IgnoreCase|RegexOptions.Compiled), "React"),
        (new Regex("vue", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Vue"),
        (new Regex("angular|angularjs", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Angular"),
        (new Regex("shopify", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Shopify"),
        (new Regex("woocommerce", RegexOptions.IgnoreCase|RegexOptions.Compiled), "WooCommerce"),
        (new Regex("bootstrap", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Bootstrap"),
        (new Regex("catalog/view/theme/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "OpenCart"),
        // BigCommerce stencil assets
        (new Regex("(?:^|/)stencil/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "BigCommerce"),
        // Security / Widgets
        (new Regex("recaptcha/(?:api|enterprise)\\.js|www\\.google\\.com/recaptcha|www\\.gstatic\\.com/recaptcha", RegexOptions.IgnoreCase|RegexOptions.Compiled), "reCAPTCHA"),
        // JS/CSS libraries
        (new Regex("swiper(?:-bundle)?(?:\\.min)?\\.(?:js|css)", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Swiper"),
    };

    private static readonly (string suffix, string tech)[] DomainSuffixes = new[]
    {
        ("medium.com","Medium"),
        ("editmysite.com","Weebly"),
        ("weebly.com","Weebly"),
        ("cloudflare.com","Cloudflare"),
        ("akamai.net","Akamai"),
        ("fastly.net","Fastly"),
        ("cloudfront.net","CloudFront"),
        ("ajax.googleapis.com","Google Hosted Libraries"),
        ("wix.com","Wix"),
        ("wixstatic.com","Wix"),
        ("squarespace-cdn.com","Squarespace"),
        ("static.squarespace.com","Squarespace"),
        ("statuspage.io","Atlassian Statuspage"),
        ("myshopify.com","Shopify"),
        ("cdn.shopify.com","Shopify"),
        ("shopifycdn.net","Shopify"),
        ("bigcommerce.com","BigCommerce"),
        ("hsforms.com","HubSpot"),
        ("hs-analytics.net","HubSpot"),
        ("hs-scripts.com","HubSpot"),
        ("vercel.app","Vercel"),
        ("netlify.app","Netlify"),
        ("herokuapp.com","Heroku"),
        ("azurewebsites.net","Azure App Service"),
        ("azureedge.net","Azure CDN")
    };
    /// <summary>
    /// Applies compiled path and domain suffix rules to infer technologies and record details.
    /// </summary>
    internal static void ApplyPathDomainRules(
        System.Collections.Generic.IEnumerable<WebStaticScanAnalysis.StaticRequest> requests,
        System.Collections.Generic.IDictionary<string, WebStaticScanAnalysis.StaticHost> hosts,
        System.Func<string,string>? getRegistrableDomain,
        System.Collections.Generic.ISet<string> outTech,
        System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        foreach (var req in requests)
        {
            string path = string.Empty;
            try { path = new System.Uri(req.FinalUrl ?? req.Url).AbsolutePath; } catch { }
            if (string.IsNullOrEmpty(path)) continue;
            foreach (var (regex, tech) in PathRules)
            {
                try {
                    var m = regex.Match(path);
                    if (m.Success) {
                        outTech.Add(tech);
                        var kind = InferKindFromPathAndContent(path, req.ContentType);
                        string? version = null;
                        for (int gi = 1; gi < m.Groups.Count; gi++) { var gv = m.Groups[gi].Value; if (!string.IsNullOrWhiteSpace(gv) && System.Text.RegularExpressions.Regex.IsMatch(gv, "^[0-9]+(?:[.][0-9]+)*$")) { version = gv; break; } }
                        details?.Add(new TechDetectionDetail { Name = tech, Version = version, SourceKind = kind, Category = GetCategory(tech), Evidence = path, Confidence = 100 });
                    }
                } catch { }
            }
        }
        foreach (var kv in hosts)
        {
            var dom = kv.Value.RegistrableDomain ?? kv.Key;
            if (getRegistrableDomain != null) dom = getRegistrableDomain(dom);
            foreach (var (suffix, tech) in DomainSuffixes)
            {
                if (dom.EndsWith(suffix, System.StringComparison.OrdinalIgnoreCase))
                {
                    outTech.Add(tech);
                    details?.Add(new TechDetectionDetail { Name = tech, SourceKind = TechEvidenceKind.DomainSuffix, Category = GetCategory(tech), Evidence = suffix, Confidence = 90 });
                }
            }
        }
    }

    private static TechEvidenceKind InferKindFromPathAndContent(string path, string? contentType)
    {
        var p = (path ?? string.Empty).ToLowerInvariant();
        var ct = (contentType ?? string.Empty).ToLowerInvariant();
        if (p.EndsWith(".js") || ct.Contains("javascript") || ct.Contains("ecmascript")) return TechEvidenceKind.ScriptSrc;
        if (p.EndsWith(".css") || ct.Contains("text/css")) return TechEvidenceKind.StylesheetSrc;
        return TechEvidenceKind.Path;
    }
}
