using System.Text.RegularExpressions;

namespace DomainDetective;

/// <summary>
/// Body HTML rules for technology detection (compiled).
/// </summary>
internal static partial class TechSignatureCatalog
{
    private static readonly (Regex regex, string tech)[] BodyRules = new[]
    {
        (new Regex("<link\\s+rel=\\\"amphtml\\\"", RegexOptions.IgnoreCase|RegexOptions.Compiled), "AMP"),
        (new Regex("<!--\\s*This site is optimized with the Yoast (?:WordPress )?SEO plugin v([\\d.]+)\\s*-", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Yoast SEO"),
        (new Regex("static\\.cloudflareinsights\\.com/beacon(?:\\.min)?\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Cloudflare Browser Insights"),
        (new Regex("<link[^>]* href=[^>]+fonts\\.(?:googleapis|google)\\.com", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Google Font API"),
        (new Regex("google-analytics\\.com/(?:ga|urchin|analytics)\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Google Analytics"),
        (new Regex("googletagmanager\\.com/gtag/js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Google Analytics"),
        (new Regex("forms/v2\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "HubSpot"),
        (new Regex("js\\.hs-analytics\\.net/analytics", RegexOptions.IgnoreCase|RegexOptions.Compiled), "HubSpot"),
        (new Regex("js\\.hs-scripts\\.com/\\d+\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "HubSpot"),
        (new Regex("js\\.hsforms\\.net/", RegexOptions.IgnoreCase|RegexOptions.Compiled), "HubSpot"),
        (new Regex("googletagmanager\\.com/gtm.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Google Tag Manager"),
        (new Regex("connect\\.facebook\\.[a-z]+/.+\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Facebook Widgets"),
        (new Regex("platform\\.twitter\\.com/widgets\\.js", RegexOptions.IgnoreCase|RegexOptions.Compiled), "Twitter Widgets")
    };
    /// <summary>
    /// Applies compiled body regex rules to infer technologies and record details.
    /// </summary>
    internal static void ApplyBodyRules(string body, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        foreach (var (regex, tech) in BodyRules)
        {
            try
            {
                var m = regex.Match(body);
                if (m.Success)
                {
                    outTech.Add(tech);
                    string? version = null;
                    for (int gi = 1; gi < m.Groups.Count; gi++) { var gv = m.Groups[gi].Value; if (!string.IsNullOrWhiteSpace(gv) && System.Text.RegularExpressions.Regex.IsMatch(gv, "^[0-9]+(?:[.][0-9]+)*$")) { version = gv; break; } }
                    details?.Add(new TechDetectionDetail { Name = tech, Version = version, SourceKind = TechEvidenceKind.Body, Category = TechSignatureCatalog.GetCategory(tech), Evidence = regex.ToString(), Confidence = 100 });
                }
            } catch { }
        }
    }
}
