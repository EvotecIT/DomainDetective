using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateTlsRptPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires exactly one TLS-RPT record to be published.</summary>
    [JsonPropertyName("requireSingleRecord")]
    public bool? RequireSingleRecord { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    /// <summary>When true, requires at least one mailto: RUA address to be present.</summary>
    [JsonPropertyName("requireMailtoRua")]
    public bool? RequireMailtoRua { get; set; }

    [JsonPropertyName("requireValidPolicy")]
    public bool? RequireValidPolicy { get; set; }

    /// <summary>When true, disallows TLS-RPT records longer than 255 characters.</summary>
    [JsonPropertyName("disallowRecordOver255")]
    public bool? DisallowRecordOver255 { get; set; }

    /// <summary>When true, disallows unknown/unrecognized TLS-RPT tags (helps detect typos).</summary>
    [JsonPropertyName("disallowUnknownTags")]
    public bool? DisallowUnknownTags { get; set; }

    /// <summary>When true, disallows invalid RUA URIs (non-mailto/non-https or invalid mail addresses).</summary>
    [JsonPropertyName("disallowInvalidRua")]
    public bool? DisallowInvalidRua { get; set; }

    /// <summary>When true, disallows HTTPS RUA endpoints (requires mailto only).</summary>
    [JsonPropertyName("disallowHttpRua")]
    public bool? DisallowHttpRua { get; set; }

    /// <summary>Allowed domain suffixes for TLSRPT rua endpoints (mailto domains / HTTPS hosts).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    public DesiredStateTlsRptPolicy Clone() {
        return new DesiredStateTlsRptPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireSingleRecord = RequireSingleRecord,
            RequireRua = RequireRua,
            RequireMailtoRua = RequireMailtoRua,
            RequireValidPolicy = RequireValidPolicy,
            DisallowRecordOver255 = DisallowRecordOver255,
            DisallowUnknownTags = DisallowUnknownTags,
            DisallowInvalidRua = DisallowInvalidRua,
            DisallowHttpRua = DisallowHttpRua,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateTlsRptPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireSingleRecord.HasValue) RequireSingleRecord = overlay.RequireSingleRecord;
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.RequireMailtoRua.HasValue) RequireMailtoRua = overlay.RequireMailtoRua;
        if (overlay.RequireValidPolicy.HasValue) RequireValidPolicy = overlay.RequireValidPolicy;
        if (overlay.DisallowRecordOver255.HasValue) DisallowRecordOver255 = overlay.DisallowRecordOver255;
        if (overlay.DisallowUnknownTags.HasValue) DisallowUnknownTags = overlay.DisallowUnknownTags;
        if (overlay.DisallowInvalidRua.HasValue) DisallowInvalidRua = overlay.DisallowInvalidRua;
        if (overlay.DisallowHttpRua.HasValue) DisallowHttpRua = overlay.DisallowHttpRua;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireSingleRecord ??= false;
        RequireMailtoRua ??= false;
        DisallowRecordOver255 ??= false;
        DisallowUnknownTags ??= false;
        DisallowInvalidRua ??= false;
        DisallowHttpRua ??= false;
    }
}
