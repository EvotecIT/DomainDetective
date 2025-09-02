using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// robots.txt handling for respectful resource discovery.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, RobotsRules?> _robotsCache = new System.Collections.Concurrent.ConcurrentDictionary<string, RobotsRules?>(System.StringComparer.OrdinalIgnoreCase);
    public sealed class RobotsRules
    {
        private readonly List<(Regex pattern, string raw)> _allow = new();
        private readonly List<(Regex pattern, string raw)> _disallow = new();
        public void AddAllow(string raw) { if (string.IsNullOrWhiteSpace(raw)) return; _allow.Add((Compile(raw), raw)); }
        public void AddDisallow(string raw) { if (string.IsNullOrWhiteSpace(raw)) return; _disallow.Add((Compile(raw), raw)); }

        public bool IsAllowed(string path)
        {
            if (string.IsNullOrEmpty(path)) return true;
            int bestAllow = 0, bestDis = 0;
            foreach (var (re, _) in _allow) { var m = re.Match(path); if (m.Success) bestAllow = Math.Max(bestAllow, m.Length); }
            foreach (var (re, _) in _disallow) { var m = re.Match(path); if (m.Success) bestDis = Math.Max(bestDis, m.Length); }
            return bestAllow >= bestDis;
        }

        private static Regex Compile(string raw)
        {
            string pattern = Regex.Escape(raw).Replace("\\*", ".*");
            if (raw.EndsWith("$"))
            {
                if (pattern.EndsWith("\\$")) pattern = pattern.Substring(0, pattern.Length - 2) + "$";
                pattern = "^" + pattern;
            }
            else
            {
                pattern = "^" + pattern + ".*";
            }
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }
    }

    internal static RobotsRules ParseRobotsRules(string text)
    {
        var rules = new RobotsRules();
        if (string.IsNullOrWhiteSpace(text)) return rules;
        bool inGlobal = false;
        foreach (var raw in text.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.StartsWith("#")) continue;
            if (line.StartsWith("User-agent:", StringComparison.OrdinalIgnoreCase))
            {
                var ua = line.Substring("User-agent:".Length).Trim();
                inGlobal = ua == "*";
                continue;
            }
            if (!inGlobal) continue;
            if (line.StartsWith("Disallow:", StringComparison.OrdinalIgnoreCase))
            {
                var path = line.Substring("Disallow:".Length).Trim();
                if (string.IsNullOrEmpty(path)) continue;
                rules.AddDisallow(path);
            }
            else if (line.StartsWith("Allow:", StringComparison.OrdinalIgnoreCase))
            {
                var path = line.Substring("Allow:".Length).Trim();
                if (string.IsNullOrEmpty(path)) continue;
                rules.AddAllow(path);
            }
        }
        return rules;
    }

    private async Task<RobotsRules?> GetRobotsRulesAsync(Uri baseUri, HttpClient http, CancellationToken token)
    {
        try
        {
            // In-memory per-host cache for the duration of the process
            var host = baseUri.Host;
            if (_robotsCache.TryGetValue(host, out var cached)) return cached;

            var robotsUrl = new Uri(baseUri, "/robots.txt");
            using var resp = await http.GetAsync(robotsUrl, token);
            if (!resp.IsSuccessStatusCode) return null;
            var text = await resp.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(text)) return null;
            var rules = ParseRobotsRules(text);
            _robotsCache[host] = rules;
            return rules;
        }
        catch { return null; }
    }
}
