namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>Provides link hint functionality.</summary>
    public sealed class LinkHint
    {
        /// <summary>Gets or sets the rel value.</summary>
        public string Rel { get; set; } = null!;
        /// <summary>Gets or sets the href value.</summary>
        public string Href { get; set; } = null!;
        /// <summary>Gets or sets the host value.</summary>
        public string? Host { get; set; }
        /// <summary>Gets or sets the first party value.</summary>
        public bool FirstParty { get; set; }
    }
}

