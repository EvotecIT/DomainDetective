using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Represents the published DMARC policy for a report.</summary>
public sealed class DmarcPolicyPublished {
    /// <summary>Domain the policy applies to.</summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>Alignment mode for DKIM.</summary>
    public string? Adkim { get; set; }

    /// <summary>Alignment mode for SPF.</summary>
    public string? Aspf { get; set; }

    /// <summary>Requested policy for the domain.</summary>
    public string? P { get; set; }

    /// <summary>Requested subdomain policy.</summary>
    public string? Sp { get; set; }

    /// <summary>Percentage of messages to which the policy is to be applied.</summary>
    public string? Pct { get; set; }

    /// <summary>Failure reporting option.</summary>
    public string? Fo { get; set; }

    /// <summary>Policy for non-existent subdomains (DMARC v2).</summary>
    public string? Np { get; set; }

    /// <summary>Human-readable interpretation of <see cref="Fo"/> (failure reporting policy).</summary>
    public string? RequestedReportingPolicy { get; set; }

    /// <summary>Any additional policy extensions.</summary>
    public Dictionary<string, string> Extensions { get; } = new(StringComparer.OrdinalIgnoreCase);
}
