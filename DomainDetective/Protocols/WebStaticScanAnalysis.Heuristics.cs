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
            var existing = new System.Collections.Generic.HashSet<string>(System.Linq.Enumerable.Select(TechDetails, d => d.Name), System.StringComparer.OrdinalIgnoreCase);
            void AddHeuristic(string name, string evidence, int confidence = 80)
            {
                TechDetections.Add(name);
                // Only add one heuristic detail per name
                if (!existing.Contains(name))
                {
                    TechDetails.Add(new TechDetectionDetail
                    {
                        Name = name,
                        SourceKind = TechEvidenceKind.Heuristic,
                        Category = TechSignatureCatalog.GetCategory(name),
                        Evidence = evidence,
                        Confidence = confidence
                    });
                    existing.Add(name);
                }
            }

            if (server.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0) AddHeuristic("nginx", $"Server: {server}", 85);
            if (server.IndexOf("Apache", StringComparison.OrdinalIgnoreCase) >= 0) AddHeuristic("Apache", $"Server: {server}", 85);
            if (server.IndexOf("IIS", StringComparison.OrdinalIgnoreCase) >= 0 || server.IndexOf("Microsoft-IIS", StringComparison.OrdinalIgnoreCase) >= 0) AddHeuristic("IIS", $"Server: {server}", 85);
            if (server.IndexOf("cloudflare", StringComparison.OrdinalIgnoreCase) >= 0) AddHeuristic("Cloudflare", $"Server: {server}", 80);

            var html = body ?? string.Empty;
            var gen = System.Text.RegularExpressions.Regex.Match(html, "<meta[^>]*name=\"generator\"[^>]*content=\"([^\"]+)\"", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (gen.Success)
            {
                var val = gen.Groups[1].Value;
                if (!string.IsNullOrWhiteSpace(val))
                {
                    var name = val.Split(' ')[0];
                    TechDetections.Add(name);
                    if (!existing.Contains(name))
                    {
                        TechDetails.Add(new TechDetectionDetail { Name = name, SourceKind = TechEvidenceKind.Heuristic, Category = TechSignatureCatalog.GetCategory(name), Evidence = $"meta generator: {val}", Confidence = 75 });
                        existing.Add(name);
                    }
                }
            }
            var seenPathEvidence = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
            foreach (var req in Requests)
            {
                var p = new Uri(req.FinalUrl ?? req.Url).AbsolutePath.ToLowerInvariant();
                void PathHit(string name)
                {
                    TechDetections.Add(name);
                    if (!existing.Contains(name) && !seenPathEvidence.Contains(name))
                    {
                        TechDetails.Add(new TechDetectionDetail { Name = name, SourceKind = TechEvidenceKind.Heuristic, Category = TechSignatureCatalog.GetCategory(name), Evidence = p, Confidence = 70 });
                        existing.Add(name);
                        seenPathEvidence.Add(name);
                    }
                }
                if (p.Contains("/wp-content/") || p.Contains("/wp-includes/")) PathHit("WordPress");
                if (p.Contains("drupal")) PathHit("Drupal");
                if (p.Contains("joomla")) PathHit("Joomla");
                if (p.Contains("shopify")) PathHit("Shopify");
                if (p.Contains("jquery")) PathHit("jQuery");
                if (p.Contains("bootstrap")) PathHit("Bootstrap");
                if (p.Contains("react") || p.Contains("react-dom")) PathHit("React");
                if (p.Contains("vue")) PathHit("Vue");
                if (p.Contains("angular") || p.Contains("angularjs")) PathHit("Angular");
            }
        }
        catch { }
    }
}
