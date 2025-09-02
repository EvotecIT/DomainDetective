using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    public sealed class LinkFanOutNode
    {
        public int RequestId { get; set; }
        public string Url { get; set; }
        public int LinkChildCount { get; set; }
        public bool FirstParty { get; set; }
        public string Host { get; set; }
    }

    public List<LinkFanOutNode> TopLinkFanOut { get; } = new();
}

