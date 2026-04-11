using System.Linq;
namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the title value.</summary>
    public string? Title { get; set; }
    /// <summary>Gets or sets the page value.</summary>
    public HttpInfo? Page { get; set; }
    /// <summary>Gets or sets the resource count value.</summary>
    public int ResourceCount { get; set; }
    /// <summary>Gets or sets the host count value.</summary>
    public int HostCount { get; set; }
    /// <summary>Gets or sets the bytes by type value.</summary>
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; } = new();
    /// <summary>Gets or sets the first party host count value.</summary>
    public int FirstPartyHostCount { get; set; }
    /// <summary>Gets or sets the third party host count value.</summary>
    public int ThirdPartyHostCount { get; set; }
    /// <summary>Gets or sets the tech value.</summary>
    public string[] Tech { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the trackers value.</summary>
    public string[] Trackers { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the top hosts by bytes value.</summary>
    public WebStaticScanHostBrief[] TopHostsByBytes { get; set; } = System.Array.Empty<WebStaticScanHostBrief>();
    /// <summary>Gets or sets the top third party by bytes value.</summary>
    public WebStaticScanHostBrief[] TopThirdPartyByBytes { get; set; } = System.Array.Empty<WebStaticScanHostBrief>();
    /// <summary>Gets or sets the tech details value.</summary>
    public TechDetectionDetail[] TechDetails { get; set; } = System.Array.Empty<TechDetectionDetail>();
    /// <summary>Gets or sets the https percent value.</summary>
    public int HttpsPercent { get; set; }
    /// <summary>Gets or sets the ipv6 percent value.</summary>
    public int Ipv6Percent { get; set; }
    /// <summary>Gets or sets the domain count value.</summary>
    public int DomainCount { get; set; }
    /// <summary>Gets or sets the subdomain count value.</summary>
    public int SubdomainCount { get; set; }
    /// <summary>Gets or sets the ip count value.</summary>
    public int IpCount { get; set; }
    /// <summary>Gets or sets the country count value.</summary>
    public int CountryCount { get; set; }
    /// <summary>Gets or sets the transfer bytes value.</summary>
    public long TransferBytes { get; set; }
    /// <summary>Gets or sets the cookies set value.</summary>
    public int CookiesSet { get; set; }
    /// <summary>Gets or sets the broken links total value.</summary>
    public int BrokenLinksTotal { get; set; }
    /// <summary>Gets or sets the broken links first party value.</summary>
    public int BrokenLinksFirstParty { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public System.Collections.Generic.IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the recommendations value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public System.Collections.Generic.IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public System.Collections.Generic.IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public WebStaticScanAnalysis Raw { get; set; } = new WebStaticScanAnalysis();
}

/// <summary>
/// Summary for a single host observed during a static scan (bytes, requests, types).
/// </summary>
public sealed class WebStaticScanHostBrief
{
    /// <summary>Gets or sets the host value.</summary>
    public string Host { get; set; } = string.Empty;
    /// <summary>Gets or sets the bytes value.</summary>
    public long Bytes { get; set; }
    /// <summary>Gets or sets the first party value.</summary>
    public bool FirstParty { get; set; }
    /// <summary>Gets or sets the requests value.</summary>
    public int Requests { get; set; }
    /// <summary>Gets or sets the bytes by type value.</summary>
    public System.Collections.Generic.Dictionary<string, long> BytesByType { get; set; } = new();
}
