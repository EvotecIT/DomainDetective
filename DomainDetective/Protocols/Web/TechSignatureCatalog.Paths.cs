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
        (new Regex("jquery.*\\.js(?:\\?ver(?:sion)?=([\\d.]+))?", RegexOptions.IgnoreCase|RegexOptions.Compiled), "jQuery"),
        (new Regex("jquery[\\.-]migrate(?:-([\\d.]+))?(?:\\.min)?\\.js(?:\\?ver=([\\d.]+))?", RegexOptions.IgnoreCase|RegexOptions.Compiled), "jQuery Migrate"),
        (new Regex("_next/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Next.js"),
        (new Regex("_nuxt/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Nuxt.js"),
        (new Regex("/skin/frontend/|/static/frontend/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Magento"),
        (new Regex("react|react-dom", RegexOptions.IgnoreCase|RegexOptions.Compiled), "React"),
        (new Regex("vue", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Vue"),
        (new Regex("angular|angularjs", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Angular"),
        (new Regex("shopify", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Shopify"),
        (new Regex("bootstrap", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Bootstrap")
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
        ("squarespace-cdn.com","Squarespace")
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
                try { if (regex.IsMatch(path)) { outTech.Add(tech); details?.Add(new TechDetectionDetail { Name = tech, Source = "Path", Evidence = path, Confidence = 100 }); } } catch { }
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
                    details?.Add(new TechDetectionDetail { Name = tech, Source = "DomainSuffix", Evidence = suffix, Confidence = 100 });
                }
            }
        }
    }
}
