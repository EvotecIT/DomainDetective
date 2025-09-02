using System;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public class StaticRequest
    {
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
        public string? CacheControl { get; set; }
        public string? ETag { get; set; }
        public string? LastModified { get; set; }
        public int? Age { get; set; }
        public string? Vary { get; set; }
        public string? Expires { get; set; }
        public DateTimeOffset? StartedAtUtc { get; set; }
        public DateTimeOffset? CompletedAtUtc { get; set; }
        public int? HeaderDurationMs { get; set; }
    }
}
