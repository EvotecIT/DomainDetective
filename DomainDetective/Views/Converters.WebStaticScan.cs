using System.Linq;
namespace DomainDetective.Views;

public static partial class Converters
{
    public static WebStaticScanInfo Convert(WebStaticScanAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        var page = analysis.MainHttpAnalysis != null ? Convert(analysis.MainHttpAnalysis) : null;
        int fp = 0, tp = 0;
        foreach (var kv in analysis.Hosts) { if (kv.Value.FirstParty) fp++; else tp++; }
        var topHosts = analysis.Hosts.Values
            .OrderByDescending(h => h.Bytes)
            .Take(10)
            .Select(h => new WebStaticScanHostBrief { Host = h.Host, Bytes = h.Bytes, FirstParty = h.FirstParty, Requests = h.RequestCount, BytesByType = h.BytesByType })
            .ToArray();
        var topThird = analysis.Hosts.Values
            .Where(h => !h.FirstParty)
            .OrderByDescending(h => h.Bytes)
            .Take(10)
            .Select(h => new WebStaticScanHostBrief { Host = h.Host, Bytes = h.Bytes, FirstParty = false, Requests = h.RequestCount, BytesByType = h.BytesByType })
            .ToArray();

        // Stats
        var reqTotal = analysis.Requests?.Count ?? 0;
        int https = 0;
        long transfer = 0;
        if (analysis.Requests != null)
        {
            foreach (var r in analysis.Requests)
            {
                try { var u = new System.Uri(r.FinalUrl ?? r.Url); if (u.Scheme == "https") https++; } catch { }
                if (r.ContentLength.HasValue) transfer += r.ContentLength.Value;
            }
        }
        var httpsPct = reqTotal > 0 ? (int)System.Math.Round(100.0 * https / reqTotal) : 0;
        // IPv6 percent by host: any IPv6 address recorded
        int ipv6Hosts = analysis.Hosts.Values.Count(h => h.IpAddresses.Any(ip => ip.Contains(':')));
        var ipv6Pct = analysis.Hosts.Count > 0 ? (int)System.Math.Round(100.0 * ipv6Hosts / analysis.Hosts.Count) : 0;
        var domains = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var h in analysis.Hosts.Values) domains.Add(h.RegistrableDomain ?? h.Host);
        int domainCount = domains.Count;
        int subdomainCount = System.Math.Max(0, (analysis.Hosts?.Count ?? 0) - domainCount);
        var ips = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        var countries = new System.Collections.Generic.HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
        foreach (var h in analysis.Hosts.Values) {
            foreach (var ip in h.IpAddresses) ips.Add(ip);
            if (!string.IsNullOrWhiteSpace(h.Country)) countries.Add(h.Country);
        }

        return new WebStaticScanInfo
        {
            Check = HealthCheckType.HTTP,
            Area = AreaForKind(HealthCheckType.HTTP),
            Subject = analysis.Subject,
            Title = analysis.PageTitle,
            Page = page,
            ResourceCount = analysis.Requests?.Count ?? 0,
            HostCount = analysis.Hosts?.Count ?? 0,
            BytesByType = analysis.BytesByType,
            FirstPartyHostCount = fp,
            ThirdPartyHostCount = tp,
            Tech = analysis.TechDetections?.ToArray() ?? System.Array.Empty<string>(),
            Trackers = analysis.TrackersUsed?.ToArray() ?? System.Array.Empty<string>(),
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
            Assessments = analysis.Assessments,
            TechDetails = analysis.TechDetails?.ToArray() ?? System.Array.Empty<TechDetectionDetail>(),
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public sealed class WebStaticScanInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public string? Title { get; set; }
    public HttpInfo? Page { get; set; }
    public int ResourceCount { get; set; }
    public int HostCount { get; set; }
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; }
    public int FirstPartyHostCount { get; set; }
    public int ThirdPartyHostCount { get; set; }
    public string[] Tech { get; set; }
    public string[] Trackers { get; set; }
    public WebStaticScanHostBrief[] TopHostsByBytes { get; set; }
    public WebStaticScanHostBrief[] TopThirdPartyByBytes { get; set; }
    public TechDetectionDetail[] TechDetails { get; set; }
    public int HttpsPercent { get; set; }
    public int Ipv6Percent { get; set; }
    public int DomainCount { get; set; }
    public int SubdomainCount { get; set; }
    public int IpCount { get; set; }
    public int CountryCount { get; set; }
    public long TransferBytes { get; set; }
    public int CookiesSet { get; set; }
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; }
    public WebStaticScanAnalysis Raw { get; set; }
}

public sealed class WebStaticScanHostBrief
{
    public string Host { get; set; }
    public long Bytes { get; set; }
    public bool FirstParty { get; set; }
    public int Requests { get; set; }
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; }
}
