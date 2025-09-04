namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Normalized resource category used for bucketing and summary stats.
    /// </summary>
    public enum ResourceCategory
    {
        /// <summary>Unrecognized or miscellaneous.</summary>
        Other = 0,
        /// <summary>Main HTML documents.</summary>
        Document,
        /// <summary>CSS stylesheets.</summary>
        Stylesheet,
        /// <summary>JavaScript files.</summary>
        Script,
        /// <summary>Images (e.g., PNG, JPEG, SVG, GIF, WebP).</summary>
        Image,
        /// <summary>Web fonts (e.g., WOFF/WOFF2/TTF/OTF).</summary>
        Font,
        /// <summary>JSON resources.</summary>
        Json
    }
}
