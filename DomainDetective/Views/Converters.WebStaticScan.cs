using System.Linq;
namespace DomainDetective.Views;

public static partial class Converters
{
    public static WebStaticScanInfo Convert(WebStaticScanAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var page = analysis.MainHttpAnalysis != null ? Convert(analysis.MainHttpAnalysis) : null;
        var hosts = analysis.Hosts;
        var requests = analysis.Requests;
        var brokenResources = analysis.BrokenResources;
        int fp = 0, tp = 0;
        foreach (var kv in hosts) { if (kv.Value.FirstParty) fp++; else tp++; }
        var topHosts = hosts.Values
            .OrderByDescending(h => h.Bytes)
            .Take(10)
            .Select(h => new WebStaticScanHostBrief { Host = h.Host, Bytes = h.Bytes, FirstParty = h.FirstParty, Requests = h.RequestCount, BytesByType = h.BytesByType })
            .ToArray();
        var topThird = hosts.Values
            .Where(h => !h.FirstParty)
            .OrderByDescending(h => h.Bytes)
            .Take(10)
            .Select(h => new WebStaticScanHostBrief { Host = h.Host, Bytes = h.Bytes, FirstParty = false, Requests = h.RequestCount, BytesByType = h.BytesByType })
            .ToArray();

        // Stats
        var reqTotal = requests.Count;
        int https = 0;
        long transfer = 0;
        foreach (var r in requests)
        {
            try { var u = new System.Uri(r.FinalUrl ?? r.Url); if (u.Scheme == "https") https++; } catch { }
            if (r.ContentLength.HasValue) transfer += r.ContentLength.Value;
        }
        var httpsPct = reqTotal > 0 ? (int)System.Math.Round(100.0 * https / reqTotal) : 0;
        // IPv6 percent by host: any IPv6 address recorded
        int ipv6Hosts = hosts.Values.Count(h => h.IpAddresses.Any(ip => ip.Contains(':')));
        var ipv6Pct = hosts.Count > 0 ? (int)System.Math.Round(100.0 * ipv6Hosts / hosts.Count) : 0;
        var domains = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var h in hosts.Values) domains.Add(h.RegistrableDomain ?? h.Host);
        int domainCount = domains.Count;
        int subdomainCount = System.Math.Max(0, hosts.Count - domainCount);
        var ips = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var countries = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var h in hosts.Values) {
            foreach (var ip in h.IpAddresses) ips.Add(ip);
            var country = h.Country;
            if (country != null && !string.IsNullOrWhiteSpace(country)) countries.Add(country);
        }

        // Broken links summary
        int brokenTotal = brokenResources.Count;
        int brokenFirstParty = 0;
        if (brokenTotal > 0)
        {
            try { brokenFirstParty = brokenResources.Count(b => b.FirstParty); } catch { }
        }

        return new WebStaticScanInfo
        {
            Check = HealthCheckType.HTTP,
            Area = AreaForKind(HealthCheckType.HTTP),
            Subject = analysis.Subject,
            Title = analysis.PageTitle,
            Page = page,
            ResourceCount = requests.Count,
            HostCount = hosts.Count,
            BytesByType = analysis.BytesByType,
            FirstPartyHostCount = fp,
            ThirdPartyHostCount = tp,
            Tech = analysis.TechDetections.ToArray(),
            Trackers = analysis.TrackersUsed.ToArray(),
            TopHostsByBytes = topHosts,
            TopThirdPartyByBytes = topThird,
            HttpsPercent = httpsPct,
            Ipv6Percent = ipv6Pct,
            DomainCount = domainCount,
            SubdomainCount = subdomainCount,
            IpCount = ips.Count,
            CountryCount = countries.Count,
            TransferBytes = transfer,
            CookiesSet = analysis.CookiesSet,
            BrokenLinksTotal = brokenTotal,
            BrokenLinksFirstParty = brokenFirstParty,
            Assessments = analysis.Assessments,
            TechDetails = analysis.TechDetails.ToArray(),
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

/// <summary>
/// View model summarizing a static website scan (HTTP resources, hosts, trackers).
/// </summary>
public sealed class WebStaticScanInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public string? Title { get; set; }
    public HttpInfo? Page { get; set; }
    public int ResourceCount { get; set; }
    public int HostCount { get; set; }
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; } = new();
    public int FirstPartyHostCount { get; set; }
    public int ThirdPartyHostCount { get; set; }
    public string[] Tech { get; set; } = System.Array.Empty<string>();
    public string[] Trackers { get; set; } = System.Array.Empty<string>();
    public WebStaticScanHostBrief[] TopHostsByBytes { get; set; } = System.Array.Empty<WebStaticScanHostBrief>();
    public WebStaticScanHostBrief[] TopThirdPartyByBytes { get; set; } = System.Array.Empty<WebStaticScanHostBrief>();
    public TechDetectionDetail[] TechDetails { get; set; } = System.Array.Empty<TechDetectionDetail>();
    public int HttpsPercent { get; set; }
    public int Ipv6Percent { get; set; }
    public int DomainCount { get; set; }
    public int SubdomainCount { get; set; }
    public int IpCount { get; set; }
    public int CountryCount { get; set; }
    public long TransferBytes { get; set; }
    public int CookiesSet { get; set; }
    public int BrokenLinksTotal { get; set; }
    public int BrokenLinksFirstParty { get; set; }
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    public WebStaticScanAnalysis Raw { get; set; } = new WebStaticScanAnalysis();
}

/// <summary>
/// Summary for a single host observed during a static scan (bytes, requests, types).
/// </summary>
public sealed class WebStaticScanHostBrief
{
    public string Host { get; set; } = string.Empty;
    public long Bytes { get; set; }
    public bool FirstParty { get; set; }
    public int Requests { get; set; }
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; } = new();
}
