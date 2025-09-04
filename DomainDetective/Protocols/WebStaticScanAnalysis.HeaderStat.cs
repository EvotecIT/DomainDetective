namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Simple name/count pair used to report top response headers for a host.
    /// </summary>
    public sealed class HeaderStat
    {
        /// <summary>Header name.</summary>
        public string Name { get; set; }
        /// <summary>Total occurrences of the header across responses.</summary>
        public int Count { get; set; }
    }
}
