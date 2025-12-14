namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class BrokenResource
    {
        public string Url { get; set; } = null!;
        public string? FinalUrl { get; set; }
        public int StatusCode { get; set; }
        public string Host { get; set; } = null!;
        public string? Category { get; set; }
        public string? Source { get; set; }
        public bool FirstParty { get; set; }
        public string? Referrer { get; set; }
    }
}

