using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Aggregated statistics for redirects between two hosts.
    /// </summary>
    public sealed class RedirectPairStat
    {
        /// <summary>Source host of the redirect.</summary>
        public string FromHost { get; set; } = null!;
        /// <summary>Destination host of the redirect.</summary>
        public string ToHost { get; set; } = null!;
        /// <summary>Total redirects observed from source to destination.</summary>
        public int Count { get; set; }
        /// <summary>Number of redirects that upgraded scheme (http→https).</summary>
        public int SchemeUpgradeCount { get; set; }
        /// <summary>Number of redirects that downgraded scheme (https→http).</summary>
        public int SchemeDowngradeCount { get; set; }
    }

    /// <summary>Redirect pair matrix keyed as "fromHost-&gt;toHost".</summary>
    public Dictionary<string, RedirectPairStat> RedirectPairs { get; } = new(System.StringComparer.OrdinalIgnoreCase);
    /// <summary>Top redirect pairs ordered by count.</summary>
    public List<RedirectPairStat> TopRedirectPairs { get; } = new();
}

