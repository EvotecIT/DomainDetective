namespace DomainDetective;

/// <summary>Boolean signal flags used for classification.</summary>
public sealed class MailDomainSignalSummary {
    public bool HasMX { get; init; }
    public bool HasNullMX { get; init; }
    public bool HasAorAAAA { get; init; }
    public bool EffectiveSpfSends { get; init; }
    public bool HasDKIM { get; init; }
    public bool HasMTASTS { get; init; }
    public bool HasTLSRPT { get; init; }
    public bool HasDANE { get; init; }
    public bool HasBIMI { get; init; }
}

