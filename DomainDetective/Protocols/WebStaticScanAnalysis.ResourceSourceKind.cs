namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Identifies how a resource was discovered during the static scan.
    /// </summary>
    public enum ResourceSourceKind
    {
        /// <summary>Discovered in the main HTML document.</summary>
        Html,
        /// <summary>Discovered while parsing CSS files.</summary>
        Css,
        /// <summary>Discovered by following anchor links.</summary>
        Link
    }
}
