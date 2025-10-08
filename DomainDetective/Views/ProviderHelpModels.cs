using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

/// <summary>
/// Represents a documentation resource for a mail/provider topic (e.g., SPF, DKIM, DMARC).
/// </summary>
public sealed class ProviderHelpTopic
{
    /// <summary>Topic name (e.g., DMARC, SPF, DKIM, ARC, BIMI, MTA-STS, TLS-RPT).</summary>
    public string Topic { get; set; } = string.Empty;
    /// <summary>URL to the documentation resource.</summary>
    public string? Url { get; set; }
    /// <summary>Optional friendly title.</summary>
    public string? Title { get; set; }
    /// <summary>Short summary of the document.</summary>
    public string? Summary { get; set; }
    /// <summary>Free-form notes.</summary>
    public string? Notes { get; set; }
    /// <summary>True when the resource is publicly accessible without login.</summary>
    public bool IsPublic { get; set; } = true;
    /// <summary>True for third-party resources (non-vendor sources).</summary>
    public bool IsThirdParty { get; set; } = false;
    /// <summary>Last verification timestamp for the link.</summary>
    public DateTime? LastVerified { get; set; }
}
