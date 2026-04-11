namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>Provides tracker detection functionality.</summary>
    public sealed class TrackerDetection
    {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = null!;
        /// <summary>Gets or sets the registrable domain value.</summary>
        public string RegistrableDomain { get; set; } = null!;
        /// <summary>Gets or sets the first party value.</summary>
        public bool FirstParty { get; set; }
        /// <summary>Gets or sets the request count value.</summary>
        public int RequestCount { get; set; }
        /// <summary>Gets or sets the bytes value.</summary>
        public long Bytes { get; set; }
        /// <summary>Gets or sets the sample urls value.</summary>
        public string[] SampleUrls { get; set; } = System.Array.Empty<string>();
        /// <summary>Gets or sets the content types value.</summary>
        public string[] ContentTypes { get; set; } = System.Array.Empty<string>();
        /// <summary>Gets or sets the evidence kind value.</summary>
        public string EvidenceKind { get; set; } = "DomainSuffix";
        /// <summary>Gets or sets the evidence value.</summary>
        public string Evidence { get; set; } = null!;
        /// <summary>Gets or sets the tracker name value.</summary>
        public string? TrackerName { get; set; }
    }
}

