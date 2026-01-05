using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateCaaPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireValid")]
    public bool? RequireValid { get; set; }

    /// <summary>Allowed issuers for <c>issue</c> tags.</summary>
    [JsonPropertyName("allowedCertificateIssuers")]
    public string[]? AllowedCertificateIssuers { get; set; }

    /// <summary>Allowed issuers for <c>issuewild</c> tags.</summary>
    [JsonPropertyName("allowedWildcardIssuers")]
    public string[]? AllowedWildcardIssuers { get; set; }

    /// <summary>When true, requires at least one iodef reporting endpoint.</summary>
    [JsonPropertyName("requireIodef")]
    public bool? RequireIodef { get; set; }

    /// <summary>Allowed domain suffixes for iodef mailto/http reporting endpoints.</summary>
    [JsonPropertyName("allowedIodefDomainSuffixes")]
    public string[]? AllowedIodefDomainSuffixes { get; set; }

    public DesiredStateCaaPolicy Clone() {
        return new DesiredStateCaaPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValid = RequireValid,
            AllowedCertificateIssuers = AllowedCertificateIssuers?.ToArray(),
            AllowedWildcardIssuers = AllowedWildcardIssuers?.ToArray(),
            RequireIodef = RequireIodef,
            AllowedIodefDomainSuffixes = AllowedIodefDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateCaaPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValid.HasValue) RequireValid = overlay.RequireValid;
        if (overlay.AllowedCertificateIssuers != null) AllowedCertificateIssuers = overlay.AllowedCertificateIssuers.ToArray();
        if (overlay.AllowedWildcardIssuers != null) AllowedWildcardIssuers = overlay.AllowedWildcardIssuers.ToArray();
        if (overlay.RequireIodef.HasValue) RequireIodef = overlay.RequireIodef;
        if (overlay.AllowedIodefDomainSuffixes != null) AllowedIodefDomainSuffixes = overlay.AllowedIodefDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireValid ??= true;
        RequireIodef ??= false;
    }
}
