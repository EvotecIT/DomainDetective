using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// robots.txt handling for respectful resource discovery.
/// </summary>
public partial class WebStaticScanAnalysis
{
    internal static HashSet<string> ParseRobotsDisallows(string text)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(text)) return result;
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
                if (string.IsNullOrWhiteSpace(path)) continue;
                if (!path.Contains("*") && !path.Contains("$")) result.Add(path);
            }
        }
        return result;
    }
    private async Task<HashSet<string>> GetRobotsDisallowsAsync(Uri baseUri, HttpClient http, CancellationToken token)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            var robotsUrl = new Uri(baseUri, "/robots.txt");
            using var resp = await http.GetAsync(robotsUrl, token);
            if (!resp.IsSuccessStatusCode) return result;
            var text = await resp.Content.ReadAsStringAsync();
            if (string.IsNullOrWhiteSpace(text)) return result;

            foreach (var d in ParseRobotsDisallows(text)) result.Add(d);
        }
        catch { }
        return result;
    }
}
