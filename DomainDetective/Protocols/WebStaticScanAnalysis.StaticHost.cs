using System;
using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Aggregated per-host metrics observed during the static web scan.
    /// </summary>
    public class StaticHost
    {
        /// <summary>Stable grouping id used to assign requests to waterfall lanes.</summary>
        public int GroupId { get; set; }
        public string Host { get; set; }
        public string? RegistrableDomain { get; set; }
        public List<string> IpAddresses { get; } = new();
        public string? Cidr { get; set; }
        public int? Asn { get; set; }
        public string? AsName { get; set; }
        public string? Country { get; set; }
        public TlsProbe.Result? Tls { get; set; }
        /// <summary>Negotiated TLS protocol string for the host (from probe).</summary>
        public string? TlsProtocolSummary { get; set; }
        /// <summary>Negotiated TLS cipher suite for the host (from probe).</summary>
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
        /// <summary>Count of responses considered cacheable (no no-store).</summary>
        public int CacheableResponses { get; set; }
        /// <summary>Count of responses flagged as non-cacheable (e.g., no-store).</summary>
        public int NonCacheableResponses { get; set; }
        /// <summary>Maximum max-age value observed (seconds).</summary>
        public int? MaxAgeSecondsMax { get; set; }
        /// <summary>Number of responses with Cache-Control: no-store.</summary>
        public int NoStoreCount { get; set; }
        /// <summary>Number of responses with Cache-Control: no-cache.</summary>
        public int NoCacheCount { get; set; }
        /// <summary>Number of responses with Cache-Control: must-revalidate.</summary>
        public int MustRevalidateCount { get; set; }
        /// <summary>Number of responses with an ETag header.</summary>
        public int ETagCount { get; set; }
        /// <summary>Number of responses with a Last-Modified header.</summary>
        public int LastModifiedCount { get; set; }
        /// <summary>Frequency of response header names (case-insensitive).</summary>
        public System.Collections.Generic.Dictionary<string,int> HeaderCounts { get; } = new(System.StringComparer.OrdinalIgnoreCase);
        /// <summary>Total number of distinct response header names observed.</summary>
        public int HeaderDistinctCount { get; set; }
        /// <summary>Top response headers by occurrence count.</summary>
        public System.Collections.Generic.List<HeaderStat> TopHeaders { get; } = new();
        /// <summary>Number of responses containing a Content-Length header.</summary>
        public int ResponsesWithContentLength { get; set; }
        /// <summary>Number of responses missing a Content-Length header.</summary>
        public int ResponsesWithoutContentLength { get; set; }
        /// <summary>Maximum Age header value observed (seconds).</summary>
        public int? AgeHeaderSecondsMax { get; set; }
        /// <summary>Sum of Age header samples (for averaging).</summary>
        public long AgeHeaderSecondsSum { get; set; }
        /// <summary>Number of Age header samples collected.</summary>
        public int AgeHeaderSamples { get; set; }
        /// <summary>Average Age header value in seconds.</summary>
        public double? AgeHeaderSecondsAvg { get; set; }
        /// <summary>Percentage of cacheable responses among seen responses.</summary>
        public int CacheablePercent { get; set; }
        /// <summary>Percentage of responses that included Content-Length.</summary>
        public int ContentLengthPresentPercent { get; set; }
        /// <summary>Total number of redirects sourced from this host.</summary>
        public int RedirectTotal { get; set; }
        /// <summary>Count of redirects upgrading scheme (http→https).</summary>
        public int RedirectSchemeUpgrade { get; set; }
        /// <summary>Count of redirects downgrading scheme (https→http).</summary>
        public int RedirectSchemeDowngrade { get; set; }
        /// <summary>Count of apex→www redirects.</summary>
        public int RedirectApexToWww { get; set; }
        /// <summary>Count of www→apex redirects.</summary>
        public int RedirectWwwToApex { get; set; }
        /// <summary>Count of redirects changing host in other ways.</summary>
        public int RedirectHostChangeOther { get; set; }
        /// <summary>Count of trailing slash added redirects.</summary>
        public int RedirectTrailingSlashAdded { get; set; }
        /// <summary>Count of trailing slash removal redirects.</summary>
        public int RedirectTrailingSlashRemoved { get; set; }
        /// <summary>Count of /index.html → slash redirects.</summary>
        public int RedirectIndexToSlash { get; set; }
        /// <summary>Count of redirects changing only the query string.</summary>
        public int RedirectQueryChangeOnly { get; set; }
        /// <summary>Count of other path-changing redirects.</summary>
        public int RedirectPathChangeOther { get; set; }
        /// <summary>Number of link-derived redirect samples used to compute averages.</summary>
        public int LinkRedirectSamples { get; set; }
        /// <summary>Sum of redirect hops for link-derived requests.</summary>
        public int LinkRedirectHopSum { get; set; }
        /// <summary>Average hop count for link-derived redirects.</summary>
        public double? LinkRedirectHopAvg { get; set; }
    }
}
