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
    /// <summary>
    /// Applies built-in header, cookie, and meta rules to infer technologies.
    /// </summary>
    /// <param name="resp">HTTP response (HEAD or GET) used for headers and cookies.</param>
    /// <param name="body">Optional HTML body snapshot to search for meta generator hints.</param>
    /// <param name="outTech">Set to append inferred technologies.</param>
    public static void ApplyHeadersCookiesMeta(HttpResponseMessage resp, string? body, System.Collections.Generic.ISet<string> outTech, System.Collections.Generic.IList<TechDetectionDetail>? details = null)
    {
        try
        {
            ApplyHeaderCookieRules(resp, outTech, details);
            if (!string.IsNullOrWhiteSpace(body)) ApplyBodyRules(body!, outTech, details);
        } catch { }
    }

    /// <summary>
    /// Applies built-in path, domain suffix, and body regex rules to infer technologies.
    /// </summary>
    /// <param name="requests">Captured static requests (URLs) for path-based matching.</param>
    /// <param name="hosts">Aggregated host entries for domain suffix checks.</param>
    /// <param name="body">Optional HTML body snapshot for regex rules.</param>
    /// <param name="getRegistrableDomain">Public Suffix List resolver for registrable domains.</param>
    /// <param name="outTech">Set to append inferred technologies.</param>
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
