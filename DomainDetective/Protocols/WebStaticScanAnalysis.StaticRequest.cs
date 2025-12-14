using System;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Represents a single HTTP resource (main page, HTML/CSS asset, or followed link) discovered during the static scan.
    /// </summary>
    /// <remarks>Contains timing, protocol, cache, security, redirect, and classification metadata.</remarks>
    public class StaticRequest
    {
        /// <summary>Sequential identifier for this request within the scan.</summary>
        public int Id { get; set; }
        /// <summary>Identifier of the logical parent request (e.g., main document for HTML assets, CSS file for CSS children, referrer page for links).</summary>
        public int? ParentId { get; set; }
        /// <summary>Stable grouping key matching the owning host to support waterfall lanes.</summary>
        public int HostGroupId { get; set; }
        /// <summary>Total number of direct children in the request graph.</summary>
        public int ChildCount { get; set; }
        /// <summary>Number of direct children discovered via links.</summary>
        public int LinkChildCount { get; set; }
        /// <summary>Maximum link depth reachable from this node relative to its own depth.</summary>
        public int MaxLinkDepthFromHere { get; set; }
        /// <summary>Original URL requested.</summary>
        public string Url { get; set; } = null!;
        /// <summary>Final host after redirects (or host parsed from <see cref="Url"/>).</summary>
        public string Host { get; set; } = null!;
        /// <summary>HTTP method used (HEAD/GET).</summary>
        public string Method { get; set; } = null!;
        /// <summary>HTTP status code returned.</summary>
        public int StatusCode { get; set; }
        /// <summary>Classification of the status code family (2xx, 3xx, 4xx, 5xx).</summary>
        public StatusClass StatusClass { get; set; }
        /// <summary>HTTP protocol version string (e.g., 1.1, 2.0, 3.0).</summary>
        public string? ProtocolVersion { get; set; }
        /// <summary>True when HTTP/2 was negotiated.</summary>
        public bool Http2 { get; set; }
        /// <summary>True when HTTP/3 was negotiated.</summary>
        public bool Http3 { get; set; }
        /// <summary>Content-Type media type value when present.</summary>
        public string? ContentType { get; set; }
        /// <summary>Top-level media supertype derived from Content-Type.</summary>
        public MediaSupertype ContentSupertype { get; set; }
        /// <summary>Content-Length value in bytes when present.</summary>
        public long? ContentLength { get; set; }
        /// <summary>Final URL after redirects (if any).</summary>
        public string? FinalUrl { get; set; }
        /// <summary>Normalized resource category used for bucketing (document/script/stylesheet/image/font/json/other).</summary>
        public ResourceCategory CategoryKind { get; set; }
        /// <summary>Discovery source label (“MAIN”, “HTML”, “CSS”, “LINK”).</summary>
        public string? Source { get; set; }
        /// <summary>Typed discovery source kind.</summary>
        public ResourceSourceKind SourceKind { get; set; }
        /// <summary>Referrer URL when discovered via links.</summary>
        public string? Referrer { get; set; }
        /// <summary>Depth for link crawling (0 at main page).</summary>
        public int Depth { get; set; }
        /// <summary>True when registrable domain matches the main page registrable domain.</summary>
        public bool FirstParty { get; set; }
        /// <summary>True when scheme, host and port match the main page final URL.</summary>
        public bool SameOrigin { get; set; }
        /// <summary>True when Strict-Transport-Security was present on the response.</summary>
        public bool HstsPresent { get; set; }
        /// <summary>Number of Set-Cookie headers present on the response.</summary>
        public int SetCookieCount { get; set; }
        /// <summary>Content-Language header value when present.</summary>
        public string? ContentLanguage { get; set; }
        /// <summary>Accept-Ranges header value when present.</summary>
        public string? AcceptRanges { get; set; }
        /// <summary>Content-Disposition header value when present.</summary>
        public string? ContentDisposition { get; set; }
        /// <summary>Comma-separated Content-Encoding values when present.</summary>
        public string? ContentEncoding { get; set; }
        /// <summary>TLS protocol negotiated for the host, stamped after enrichment when available.</summary>
        public string? TlsProtocol { get; set; }
        /// <summary>TLS cipher suite negotiated for the host, stamped after enrichment when available.</summary>
        public string? TlsCipherSuite { get; set; }
        /// <summary>Leaf certificate subject when available from host TLS probe.</summary>
        public string? TlsCertSubject { get; set; }
        /// <summary>Leaf certificate issuer when available from host TLS probe.</summary>
        public string? TlsCertIssuer { get; set; }
        /// <summary>Leaf certificate expiration (NotAfter) when available from host TLS probe.</summary>
        public System.DateTime? TlsCertNotAfter { get; set; }
        /// <summary>Leaf certificate thumbprint when available from host TLS probe.</summary>
        public string? TlsCertThumbprint { get; set; }
        /// <summary>Cache-Control header value, if set (response or content).</summary>
        public string? CacheControl { get; set; }
        /// <summary>ETag header value when present.</summary>
        public string? ETag { get; set; }
        /// <summary>Last-Modified header value when present.</summary>
        public string? LastModified { get; set; }
        /// <summary>Age header value (seconds) when present.</summary>
        public int? Age { get; set; }
        /// <summary>Vary header value when present.</summary>
        public string? Vary { get; set; }
        /// <summary>Expires header value when present.</summary>
        public string? Expires { get; set; }
        /// <summary>Alt-Svc header value when present.</summary>
        public string? AltSvc { get; set; }
        /// <summary>Raw Link header value when present.</summary>
        public string? LinkHeader { get; set; }
        /// <summary>Number of rel=preload entries parsed from the Link header.</summary>
        public int? PreloadLinkCount { get; set; }
        /// <summary>Comma-separated list of distinct as= types from rel=preload entries.</summary>
        public string? PreloadAsTypes { get; set; }
        /// <summary>Timestamp when the request attempt started (UTC).</summary>
        public DateTimeOffset? StartedAtUtc { get; set; }
        /// <summary>Timestamp when response headers were received (UTC).</summary>
        public DateTimeOffset? CompletedAtUtc { get; set; }
        /// <summary>Elapsed time (ms) to receive response headers.</summary>
        public int? HeaderDurationMs { get; set; }
        /// <summary>Approximate size of response headers in bytes.</summary>
        public int? ResponseHeaderBytes { get; set; }
        /// <summary>True when the final URL differs from the original request URL.</summary>
        public bool WasRedirected { get; set; }
        /// <summary>Classification of the redirect from original URL to final URL (when redirected).</summary>
        public RedirectKind RedirectKind { get; set; }
        /// <summary>Estimated number of redirect hops for this request (1 for single-step; main document uses actual chain length).</summary>
        public int RedirectHopCount { get; set; }
        /// <summary>Destination host of the redirect.</summary>
        public string? RedirectToHost { get; set; }
        /// <summary>Destination scheme of the redirect (e.g., https).</summary>
        public string? RedirectToScheme { get; set; }
        /// <summary>Server-Timing header value when present (raw; aggregated separately).</summary>
        public string? ServerTiming { get; set; }
        /// <summary>Access-Control-Allow-Origin value when present (per-request echo).</summary>
        public string? AccessControlAllowOrigin { get; set; }
        /// <summary>Access-Control-Allow-Methods value when present (per-request echo).</summary>
        public string? AccessControlAllowMethods { get; set; }
        /// <summary>Access-Control-Allow-Headers value when present (per-request echo).</summary>
        public string? AccessControlAllowHeaders { get; set; }
        /// <summary>Access-Control-Allow-Credentials value (true/false) when present.</summary>
        public bool? AccessControlAllowCredentials { get; set; }
        /// <summary>Percentage of header bytes over body bytes when both are known.</summary>
        public int? HeaderOverBodyPct { get; set; }
    }
}
