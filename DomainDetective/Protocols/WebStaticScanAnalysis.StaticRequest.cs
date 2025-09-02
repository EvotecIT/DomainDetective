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
        public string? ContentType { get; set; }
        public long? ContentLength { get; set; }
        public string? FinalUrl { get; set; }
        public string? Category { get; set; }
        public string? Source { get; set; }
        public ResourceSourceKind SourceKind { get; set; }
        public string? Referrer { get; set; }
        public int Depth { get; set; }
        public DateTimeOffset? StartedAtUtc { get; set; }
        public DateTimeOffset? CompletedAtUtc { get; set; }
        public int? HeaderDurationMs { get; set; }
    }
}
