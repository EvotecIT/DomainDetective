using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public sealed class ProviderHelpTopic
{
    public string Topic { get; set; } = string.Empty; // e.g., DMARC, SPF, DKIM, MTA-STS, TLS-RPT, Deliverability
    public string? Url { get; set; }
    public string? Title { get; set; }
    public string? Summary { get; set; }
    public string? Notes { get; set; }
    public bool IsPublic { get; set; } = true; // false => requires login
    public bool IsThirdParty { get; set; } = false; // true => non-vendor source
    public DateTime? LastVerified { get; set; }
}

