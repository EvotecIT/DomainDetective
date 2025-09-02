using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class RedirectPairStat
    {
        public string FromHost { get; set; }
        public string ToHost { get; set; }
        public int Count { get; set; }
        public int SchemeUpgradeCount { get; set; }
        public int SchemeDowngradeCount { get; set; }
    }

    public Dictionary<string, RedirectPairStat> RedirectPairs { get; } = new(System.StringComparer.OrdinalIgnoreCase);
    public List<RedirectPairStat> TopRedirectPairs { get; } = new();
}

