using System.Collections.Generic;

namespace DomainDetective;

public partial class WebStaticScanAnalysis
{
    /// <summary>
    /// Summarizes high fan-out pages (by link-derived children) to identify hubs.
    /// </summary>
    public sealed class LinkFanOutNode
    {
        /// <summary>Request identifier of the node.</summary>
        public int RequestId { get; set; }
        /// <summary>Final URL (or original URL if not redirected).</summary>
        public string Url { get; set; }
        /// <summary>Number of child edges derived from links.</summary>
        public int LinkChildCount { get; set; }
        /// <summary>True when the node is first-party.</summary>
        public bool FirstParty { get; set; }
        /// <summary>Host of the node.</summary>
        public string Host { get; set; }
    }

    /// <summary>Top nodes with the highest number of link-derived children.</summary>
    public List<LinkFanOutNode> TopLinkFanOut { get; } = new();
}

