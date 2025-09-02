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
                if (regex.IsMatch(body))
                {
                    outTech.Add(tech);
                    details?.Add(new TechDetectionDetail { Name = tech, Source = "Body", Evidence = regex.ToString(), Confidence = 100 });
                }
            } catch { }
        }
    }
}
