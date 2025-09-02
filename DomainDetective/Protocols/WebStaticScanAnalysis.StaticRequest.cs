using System;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public class StaticRequest
    {
        public int Id { get; set; }
        public int? ParentId { get; set; }
        public int HostGroupId { get; set; }
        public int ChildCount { get; set; }
        public int LinkChildCount { get; set; }
        public int MaxLinkDepthFromHere { get; set; }
        public string Url { get; set; }
        public string Host { get; set; }
        public string Method { get; set; }
        public int StatusCode { get; set; }
        public StatusClass StatusClass { get; set; }
        public string? ProtocolVersion { get; set; }
        public bool Http2 { get; set; }
        public bool Http3 { get; set; }
        public string? ContentType { get; set; }
        public MediaSupertype ContentSupertype { get; set; }
        public long? ContentLength { get; set; }
        public string? FinalUrl { get; set; }
        public ResourceCategory CategoryKind { get; set; }
        public string? Source { get; set; }
        public ResourceSourceKind SourceKind { get; set; }
        public string? Referrer { get; set; }
        public int Depth { get; set; }
        public bool FirstParty { get; set; }
        public bool SameOrigin { get; set; }
        public bool HstsPresent { get; set; }
        public int SetCookieCount { get; set; }
        public string? ContentLanguage { get; set; }
        public string? AcceptRanges { get; set; }
        public string? ContentDisposition { get; set; }
        public string? ContentEncoding { get; set; }
        public string? TlsProtocol { get; set; }
        public string? TlsCipherSuite { get; set; }
        public string? TlsCertSubject { get; set; }
        public string? TlsCertIssuer { get; set; }
        public System.DateTime? TlsCertNotAfter { get; set; }
        public string? TlsCertThumbprint { get; set; }
        public string? CacheControl { get; set; }
        public string? ETag { get; set; }
        public string? LastModified { get; set; }
        public int? Age { get; set; }
        public string? Vary { get; set; }
        public string? Expires { get; set; }
        public string? AltSvc { get; set; }
        public string? LinkHeader { get; set; }
        public int? PreloadLinkCount { get; set; }
        public string? PreloadAsTypes { get; set; }
        public DateTimeOffset? StartedAtUtc { get; set; }
        public DateTimeOffset? CompletedAtUtc { get; set; }
        public int? HeaderDurationMs { get; set; }
        public int? ResponseHeaderBytes { get; set; }
        public bool WasRedirected { get; set; }
        public RedirectKind RedirectKind { get; set; }
        public int RedirectHopCount { get; set; }
        public string? RedirectToHost { get; set; }
        public string? RedirectToScheme { get; set; }
        public string? ServerTiming { get; set; }
        public string? AccessControlAllowOrigin { get; set; }
        public string? AccessControlAllowMethods { get; set; }
        public string? AccessControlAllowHeaders { get; set; }
        public bool? AccessControlAllowCredentials { get; set; }
        public int? HeaderOverBodyPct { get; set; }
    }
}
