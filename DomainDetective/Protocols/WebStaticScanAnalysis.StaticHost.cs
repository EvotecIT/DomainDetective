using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public class StaticHost
    {
        public int GroupId { get; set; }
        public string Host { get; set; }
        public string? RegistrableDomain { get; set; }
        public List<string> IpAddresses { get; } = new();
        public string? Cidr { get; set; }
        public int? Asn { get; set; }
        public string? AsName { get; set; }
        public string? Country { get; set; }
        public TlsProbe.Result? Tls { get; set; }
        public string? TlsProtocolSummary { get; set; }
        public string? TlsCipherSuiteSummary { get; set; }
        public int RequestCount { get; set; }
        public long Bytes { get; set; }
        public bool FirstParty { get; set; }
        public Dictionary<string, long> BytesByType { get; } = new(StringComparer.OrdinalIgnoreCase);
        public bool HasIPv6 { get; set; }
        public int? ATtlMin { get; set; }
        public int? ATtlMax { get; set; }
        public int? AAAATtlMin { get; set; }
        public int? AAAATtlMax { get; set; }
        public string? EdgeProvider { get; set; }
        public string? EdgePop { get; set; }
        public string? EdgeCacheStatus { get; set; }
        public string? EdgePopCity { get; set; }
        public string? EdgePopCountry { get; set; }
        public string? EdgePopRegion { get; set; }
        public string? ServerHeader { get; set; }
        public bool HostHstsPresent { get; set; }
        public bool CorsAnyOrigin { get; set; }
        // Cache behavior aggregates
        public int CacheableResponses { get; set; }
        public int NonCacheableResponses { get; set; }
        public int? MaxAgeSecondsMax { get; set; }
        public int NoStoreCount { get; set; }
        public int NoCacheCount { get; set; }
        public int MustRevalidateCount { get; set; }
        public int ETagCount { get; set; }
        public int LastModifiedCount { get; set; }
        // Header frequency (case-insensitive)
        public System.Collections.Generic.Dictionary<string,int> HeaderCounts { get; } = new(System.StringComparer.OrdinalIgnoreCase);
        public int HeaderDistinctCount { get; set; }
        public System.Collections.Generic.List<HeaderStat> TopHeaders { get; } = new();
        // Content-Length presence
        public int ResponsesWithContentLength { get; set; }
        public int ResponsesWithoutContentLength { get; set; }
        // Age header aggregations
        public int? AgeHeaderSecondsMax { get; set; }
        public long AgeHeaderSecondsSum { get; set; }
        public int AgeHeaderSamples { get; set; }
        public double? AgeHeaderSecondsAvg { get; set; }
        // Derived scan-level percents
        public int CacheablePercent { get; set; }
        public int ContentLengthPresentPercent { get; set; }
        // Redirect taxonomy counters
        public int RedirectTotal { get; set; }
        public int RedirectSchemeUpgrade { get; set; }
        public int RedirectSchemeDowngrade { get; set; }
        public int RedirectApexToWww { get; set; }
        public int RedirectWwwToApex { get; set; }
        public int RedirectHostChangeOther { get; set; }
        public int RedirectTrailingSlashAdded { get; set; }
        public int RedirectTrailingSlashRemoved { get; set; }
        public int RedirectIndexToSlash { get; set; }
        public int RedirectQueryChangeOnly { get; set; }
        public int RedirectPathChangeOther { get; set; }
        // Link-only redirect hop stats
        public int LinkRedirectSamples { get; set; }
        public int LinkRedirectHopSum { get; set; }
        public double? LinkRedirectHopAvg { get; set; }
    }
}
