using System.Collections.Generic;

namespace DomainDetective;

/// <summary>MX lookup results for an email domain.</summary>
public sealed class EmailAddressMxDetails {
    /// <summary>True when a MX/A/AAAA lookup was attempted.</summary>
    public bool Checked { get; set; }

    /// <summary>True when domain appears to accept mail.</summary>
    public bool AcceptsMail { get; set; }

    /// <summary>True when a NULL MX record was detected.</summary>
    public bool HasNullMx { get; set; }

    /// <summary>True when A/AAAA fallback was used in absence of MX records.</summary>
    public bool UsedApexFallback { get; set; }

    /// <summary>MX host records returned by DNS.</summary>
    public List<string> Records { get; set; } = new();

    /// <summary>Selected primary MX host (lowest preference).</summary>
    public string? PrimaryHost { get; set; }

    /// <summary>Preference value for the primary MX host.</summary>
    public int? PrimaryPriority { get; set; }

    /// <summary>Optional error detail.</summary>
    public string? Error { get; set; }
}
