using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateSpfPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the SPF record to be syntactically valid (v=spf1, no obvious syntax errors).</summary>
    [JsonPropertyName("requireValidRecord")]
    public bool? RequireValidRecord { get; set; }

    /// <summary>When true, requires exactly one SPF record to be published.</summary>
    [JsonPropertyName("requireSingleRecord")]
    public bool? RequireSingleRecord { get; set; }

    /// <summary>When true, requires SPF to effectively authorize outbound senders after resolving include/redirect chains.</summary>
    [JsonPropertyName("requireEffectiveSpfSends")]
    public bool? RequireEffectiveSpfSends { get; set; }

    /// <summary>Allowed all mechanisms, as SPF syntax strings (e.g., "-all", "~all").</summary>
    [JsonPropertyName("allowedAllMechanisms")]
    public string[]? AllowedAllMechanisms { get; set; }

    /// <summary>When true, requires the SPF record to include an all mechanism (e.g., -all, ~all).</summary>
    [JsonPropertyName("requireAllMechanism")]
    public bool? RequireAllMechanism { get; set; }

    [JsonPropertyName("maxDnsLookups")]
    public int? MaxDnsLookups { get; set; }

    [JsonPropertyName("requireDenyAll")]
    public bool? RequireDenyAll { get; set; }

    /// <summary>Include domains that must be present in the SPF record (top-level or resolved chain).</summary>
    [JsonPropertyName("requiredIncludeDomains")]
    public string[]? RequiredIncludeDomains { get; set; }

    /// <summary>When true, checks required include domains against the resolved include chain.</summary>
    [JsonPropertyName("matchResolvedIncludes")]
    public bool? MatchResolvedIncludes { get; set; }

    /// <summary>When true, disallows the use of the SPF ptr mechanism.</summary>
    [JsonPropertyName("disallowPtr")]
    public bool? DisallowPtr { get; set; }

    /// <summary>When true, disallows unknown mechanisms/modifiers.</summary>
    [JsonPropertyName("disallowUnknownMechanisms")]
    public bool? DisallowUnknownMechanisms { get; set; }

    /// <summary>When true, disallows the redirect= modifier.</summary>
    [JsonPropertyName("disallowRedirect")]
    public bool? DisallowRedirect { get; set; }

    /// <summary>When true, requires the redirect= modifier to be present.</summary>
    [JsonPropertyName("requireRedirect")]
    public bool? RequireRedirect { get; set; }

    /// <summary>When true, disallows exp= (explanation) modifier.</summary>
    [JsonPropertyName("disallowExp")]
    public bool? DisallowExp { get; set; }

    /// <summary>When true, disallows SPF PermError results.</summary>
    [JsonPropertyName("disallowPermError")]
    public bool? DisallowPermError { get; set; }

    /// <summary>When true, disallows SPF records resolved through a CNAME alias.</summary>
    [JsonPropertyName("disallowCname")]
    public bool? DisallowCname { get; set; }

    /// <summary>Allowed domain suffixes for redirect= target.</summary>
    [JsonPropertyName("allowedRedirectDomainSuffixes")]
    public string[]? AllowedRedirectDomainSuffixes { get; set; }

    public DesiredStateSpfPolicy Clone() {
        return new DesiredStateSpfPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValidRecord = RequireValidRecord,
            RequireSingleRecord = RequireSingleRecord,
            RequireEffectiveSpfSends = RequireEffectiveSpfSends,
            AllowedAllMechanisms = AllowedAllMechanisms?.ToArray(),
            RequireAllMechanism = RequireAllMechanism,
            MaxDnsLookups = MaxDnsLookups,
            RequireDenyAll = RequireDenyAll,
            RequiredIncludeDomains = RequiredIncludeDomains?.ToArray(),
            MatchResolvedIncludes = MatchResolvedIncludes,
            DisallowPtr = DisallowPtr,
            DisallowUnknownMechanisms = DisallowUnknownMechanisms,
            DisallowRedirect = DisallowRedirect,
            RequireRedirect = RequireRedirect,
            DisallowExp = DisallowExp,
            DisallowPermError = DisallowPermError,
            DisallowCname = DisallowCname,
            AllowedRedirectDomainSuffixes = AllowedRedirectDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateSpfPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValidRecord.HasValue) RequireValidRecord = overlay.RequireValidRecord;
        if (overlay.RequireSingleRecord.HasValue) RequireSingleRecord = overlay.RequireSingleRecord;
        if (overlay.RequireEffectiveSpfSends.HasValue) RequireEffectiveSpfSends = overlay.RequireEffectiveSpfSends;
        if (overlay.AllowedAllMechanisms != null) AllowedAllMechanisms = overlay.AllowedAllMechanisms.ToArray();
        if (overlay.RequireAllMechanism.HasValue) RequireAllMechanism = overlay.RequireAllMechanism;
        if (overlay.MaxDnsLookups.HasValue) MaxDnsLookups = overlay.MaxDnsLookups;
        if (overlay.RequireDenyAll.HasValue) RequireDenyAll = overlay.RequireDenyAll;
        if (overlay.RequiredIncludeDomains != null) RequiredIncludeDomains = overlay.RequiredIncludeDomains.ToArray();
        if (overlay.MatchResolvedIncludes.HasValue) MatchResolvedIncludes = overlay.MatchResolvedIncludes;
        if (overlay.DisallowPtr.HasValue) DisallowPtr = overlay.DisallowPtr;
        if (overlay.DisallowUnknownMechanisms.HasValue) DisallowUnknownMechanisms = overlay.DisallowUnknownMechanisms;
        if (overlay.DisallowRedirect.HasValue) DisallowRedirect = overlay.DisallowRedirect;
        if (overlay.RequireRedirect.HasValue) RequireRedirect = overlay.RequireRedirect;
        if (overlay.DisallowExp.HasValue) DisallowExp = overlay.DisallowExp;
        if (overlay.DisallowPermError.HasValue) DisallowPermError = overlay.DisallowPermError;
        if (overlay.DisallowCname.HasValue) DisallowCname = overlay.DisallowCname;
        if (overlay.AllowedRedirectDomainSuffixes != null) AllowedRedirectDomainSuffixes = overlay.AllowedRedirectDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireValidRecord ??= true;
        RequireSingleRecord ??= true;
        RequireEffectiveSpfSends ??= false;
        RequireAllMechanism ??= false;
        RequireDenyAll ??= false;
        MatchResolvedIncludes ??= true;
        DisallowPtr ??= false;
        DisallowUnknownMechanisms ??= false;
        DisallowRedirect ??= false;
        RequireRedirect ??= false;
        DisallowExp ??= false;
        DisallowPermError ??= false;
        DisallowCname ??= false;
    }
}
