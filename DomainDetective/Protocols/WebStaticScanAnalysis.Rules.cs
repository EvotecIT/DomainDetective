using System;
using System.IO;
using System.Net.Http;
using System.Text.Json;

namespace DomainDetective;

/// <summary>
/// JSON rule loading and application split from the core web static scan logic.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private void LoadTechRulesOnce()
    {
        if (_techRulesTried) return;
        _techRulesTried = true;
        try
        {
            string? path = TechRulesPath;
            if (!string.IsNullOrWhiteSpace(path) && File.Exists(path))
            {
                var json = File.ReadAllText(path);
                _techRules = JsonSerializer.Deserialize<TechRuleSet>(json, Helpers.JsonOptions.Default);
            }
        }
        catch { _techRules = null; }
    }

    /// <summary>
    /// Applies optional JSON header/cookie/meta rules (when loaded) to infer technologies.
    /// </summary>
    private void ApplyHeaderCookieMetaRules(HttpResponseMessage resp, string? body)
    {
        LoadTechRulesOnce(); if (_techRules == null) return;
        try
        {
            // Headers
            if (_techRules.Headers != null)
            {
                foreach (var rule in _techRules.Headers)
                {
                    if (rule == null || string.IsNullOrEmpty(rule.Name) || string.IsNullOrEmpty(rule.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                    if (resp.Headers.TryGetValues(rule.Name, out var vals) || (resp.Content != null && resp.Content.Headers.TryGetValues(rule.Name, out vals)))
                    {
                        foreach (var v in vals)
                        {
                            if (!string.IsNullOrEmpty(v) && v.IndexOf(rule.Contains, StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                TechDetections.Add(rule.Tech);
                            }
                        }
                    }
                }
            }
            // Cookies
            if (_techRules.Cookies != null && resp.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var c in cookies)
                {
                    foreach (var rule in _techRules.Cookies)
                    {
                        if (rule == null || string.IsNullOrEmpty(rule.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (!string.IsNullOrEmpty(c) && c.IndexOf(rule.Contains, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            // Meta
            if (_techRules.Meta != null && body != null && body.Length > 0)
            {
                foreach (var rule in _techRules.Meta)
                {
                    if (rule == null || string.IsNullOrEmpty(rule.Name) || string.IsNullOrEmpty(rule.Contains) || string.IsNullOrEmpty(rule.Tech)) continue;
                    var pattern = $"<meta[^>]*name=\"{System.Text.RegularExpressions.Regex.Escape(rule.Name)}\"[^>]*content=\"([^\"]*)\"";
                    var m = System.Text.RegularExpressions.Regex.Match(body, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    if (m.Success && (m.Groups[1].Value ?? string.Empty).IndexOf(rule.Contains, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        TechDetections.Add(rule.Tech);
                    }
                }
            }
        }
        catch { }
    }

    /// <summary>
    /// Applies optional JSON path/domain/body rules (when loaded) to infer technologies.
    /// </summary>
    private void ApplyPathAndDomainRules()
    {
        LoadTechRulesOnce(); if (_techRules == null) return;
        try
        {
            if (_techRules.Paths != null)
            {
                foreach (var req in Requests)
                {
                    var p = string.Empty;
                    try { p = new Uri(req.FinalUrl ?? req.Url).AbsolutePath; } catch { continue; }
                    foreach (var rule in _techRules.Paths)
                    {
                        if (rule == null || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (!string.IsNullOrEmpty(rule.Regex))
                        {
                            try { if (System.Text.RegularExpressions.Regex.IsMatch(p, rule.Regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase)) TechDetections.Add(rule.Tech); } catch { }
                        }
                        else if (!string.IsNullOrEmpty(rule.Contains))
                        {
                            if (p.IndexOf(rule.Contains, StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            if (_techRules.Domains != null)
            {
                foreach (var kv in Hosts)
                {
                    var dom = kv.Value.RegistrableDomain ?? kv.Key;
                    foreach (var rule in _techRules.Domains)
                    {
                        if (rule == null || string.IsNullOrEmpty(rule.Suffix) || string.IsNullOrEmpty(rule.Tech)) continue;
                        if (dom.EndsWith(rule.Suffix, StringComparison.OrdinalIgnoreCase))
                        {
                            TechDetections.Add(rule.Tech);
                        }
                    }
                }
            }
            var mainBody = MainHttpAnalysis?.Body;
            if (_techRules.Body != null && mainBody != null && !string.IsNullOrWhiteSpace(mainBody))
            {
                var html = mainBody;
                foreach (var rule in _techRules.Body)
                {
                    if (rule == null || string.IsNullOrEmpty(rule.Regex) || string.IsNullOrEmpty(rule.Tech)) continue;
                    try { if (System.Text.RegularExpressions.Regex.IsMatch(html, rule.Regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase)) TechDetections.Add(rule.Tech); } catch { }
                }
            }
        }
        catch { }
    }
}

