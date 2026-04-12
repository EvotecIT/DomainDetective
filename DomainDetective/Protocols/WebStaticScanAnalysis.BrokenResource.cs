namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>Provides broken resource functionality.</summary>
    public sealed class BrokenResource
    {
        /// <summary>Gets or sets the url value.</summary>
        public string Url { get; set; } = null!;
        /// <summary>Gets or sets the final url value.</summary>
        public string? FinalUrl { get; set; }
        /// <summary>Gets or sets the status code value.</summary>
        public int StatusCode { get; set; }
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = null!;
        /// <summary>Gets or sets the category value.</summary>
        public string? Category { get; set; }
        /// <summary>Gets or sets the source value.</summary>
        public string? Source { get; set; }
        /// <summary>Gets or sets the first party value.</summary>
        public bool FirstParty { get; set; }
        /// <summary>Gets or sets the referrer value.</summary>
        public string? Referrer { get; set; }
    }
}

