using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateSecurityTxtPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireValid")]
    public bool? RequireValid { get; set; }

    /// <summary>When true, disallows fallback to HTTP when HTTPS retrieval fails.</summary>
    [JsonPropertyName("disallowFallback")]
    public bool? DisallowFallback { get; set; }

    [JsonPropertyName("requirePgpSigned")]
    public bool? RequirePgpSigned { get; set; }

    [JsonPropertyName("requireContactEmail")]
    public bool? RequireContactEmail { get; set; }

    /// <summary>Allowed suffixes for domains used in Contact mail addresses.</summary>
    [JsonPropertyName("allowedContactEmailDomainSuffixes")]
    public string[]? AllowedContactEmailDomainSuffixes { get; set; }

    public DesiredStateSecurityTxtPolicy Clone() {
        return new DesiredStateSecurityTxtPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValid = RequireValid,
            DisallowFallback = DisallowFallback,
            RequirePgpSigned = RequirePgpSigned,
            RequireContactEmail = RequireContactEmail,
            AllowedContactEmailDomainSuffixes = AllowedContactEmailDomainSuffixes != null ? (string[])AllowedContactEmailDomainSuffixes.Clone() : null
        };
    }

    public void Apply(DesiredStateSecurityTxtPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValid.HasValue) RequireValid = overlay.RequireValid;
        if (overlay.DisallowFallback.HasValue) DisallowFallback = overlay.DisallowFallback;
        if (overlay.RequirePgpSigned.HasValue) RequirePgpSigned = overlay.RequirePgpSigned;
        if (overlay.RequireContactEmail.HasValue) RequireContactEmail = overlay.RequireContactEmail;
        if (overlay.AllowedContactEmailDomainSuffixes != null) AllowedContactEmailDomainSuffixes = overlay.AllowedContactEmailDomainSuffixes;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireValid ??= false;
        DisallowFallback ??= false;
        RequirePgpSigned ??= false;
        RequireContactEmail ??= false;
    }
}

