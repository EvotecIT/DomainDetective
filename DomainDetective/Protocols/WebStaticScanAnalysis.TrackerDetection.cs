namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class TrackerDetection
    {
        public string Host { get; set; } = null!;
        public string RegistrableDomain { get; set; } = null!;
        public bool FirstParty { get; set; }
        public int RequestCount { get; set; }
        public long Bytes { get; set; }
        public string[] SampleUrls { get; set; } = System.Array.Empty<string>();
        public string[] ContentTypes { get; set; } = System.Array.Empty<string>();
        public string EvidenceKind { get; set; } = "DomainSuffix";
        public string Evidence { get; set; } = null!;
        public string? TrackerName { get; set; }
    }
}

