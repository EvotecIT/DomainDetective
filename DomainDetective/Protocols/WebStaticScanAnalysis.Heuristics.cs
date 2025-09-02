using System;

namespace DomainDetective;

/// <summary>
/// Heuristic detections that are lightweight and used to enrich compiled rules.
/// </summary>
public partial class WebStaticScanAnalysis
{
    private void ApplyHeuristicDetections(HttpAnalysis main, string? body)
    {
        try
        {
            var server = main.ServerHeader ?? string.Empty;
            if (server.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("nginx");
            if (server.IndexOf("Apache", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("Apache");
            if (server.IndexOf("IIS", StringComparison.OrdinalIgnoreCase) >= 0 || server.IndexOf("Microsoft-IIS", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("IIS");
            if (server.IndexOf("cloudflare", StringComparison.OrdinalIgnoreCase) >= 0) TechDetections.Add("Cloudflare");

            var html = body ?? string.Empty;
            var gen = System.Text.RegularExpressions.Regex.Match(html, "<meta[^>]*name=\"generator\"[^>]*content=\"([^\"]+)\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (gen.Success)
            {
                var val = gen.Groups[1].Value;
                if (!string.IsNullOrWhiteSpace(val)) TechDetections.Add(val.Split(' ')[0]);
            }
            foreach (var req in Requests)
            {
                var p = new Uri(req.FinalUrl ?? req.Url).AbsolutePath.ToLowerInvariant();
                if (p.Contains("/wp-content/") || p.Contains("/wp-includes/")) TechDetections.Add("WordPress");
                if (p.Contains("drupal")) TechDetections.Add("Drupal");
                if (p.Contains("joomla")) TechDetections.Add("Joomla");
                if (p.Contains("shopify")) TechDetections.Add("Shopify");
                if (p.Contains("jquery")) TechDetections.Add("jQuery");
                if (p.Contains("bootstrap")) TechDetections.Add("Bootstrap");
                if (p.Contains("react") || p.Contains("react-dom")) TechDetections.Add("React");
                if (p.Contains("vue")) TechDetections.Add("Vue");
                if (p.Contains("angular") || p.Contains("angularjs")) TechDetections.Add("Angular");
            }
        }
        catch { }
    }
}

