using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state security txt policy functionality.</summary>
public sealed class DesiredStateSecurityTxtPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Gets or sets the require valid value.</summary>
    [JsonPropertyName("requireValid")]
    public bool? RequireValid { get; set; }

    /// <summary>When true, disallows fallback to HTTP when HTTPS retrieval fails.</summary>
    [JsonPropertyName("disallowFallback")]
    public bool? DisallowFallback { get; set; }

    /// <summary>Gets or sets the require pgp signed value.</summary>
    [JsonPropertyName("requirePgpSigned")]
    public bool? RequirePgpSigned { get; set; }

    /// <summary>Gets or sets the require contact email value.</summary>
    [JsonPropertyName("requireContactEmail")]
    public bool? RequireContactEmail { get; set; }

    /// <summary>Allowed suffixes for domains used in Contact mail addresses.</summary>
    [JsonPropertyName("allowedContactEmailDomainSuffixes")]
    public string[]? AllowedContactEmailDomainSuffixes { get; set; }

    /// <summary>Executes the clone operation.</summary>
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

    /// <summary>Executes the apply operation.</summary>
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

