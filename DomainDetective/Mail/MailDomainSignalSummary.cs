namespace DomainDetective;

/// <summary>Boolean signal flags used for classification.</summary>
public sealed class MailDomainSignalSummary {
    /// <summary>Gets or sets the has mx value.</summary>
    public bool HasMX { get; init; }
    /// <summary>Gets or sets the has null mx value.</summary>
    public bool HasNullMX { get; init; }
    /// <summary>Gets or sets the has aor aaaa value.</summary>
    public bool HasAorAAAA { get; init; }
    /// <summary>Gets or sets the effective spf sends value.</summary>
    public bool EffectiveSpfSends { get; init; }
    /// <summary>Gets or sets the has dkim value.</summary>
    public bool HasDKIM { get; init; }
    /// <summary>Gets or sets the has mtasts value.</summary>
    public bool HasMTASTS { get; init; }
    /// <summary>Gets or sets the has tlsrpt value.</summary>
    public bool HasTLSRPT { get; init; }
    /// <summary>Gets or sets the has dane value.</summary>
    public bool HasDANE { get; init; }
    /// <summary>Gets or sets the has bimi value.</summary>
    public bool HasBIMI { get; init; }
}

