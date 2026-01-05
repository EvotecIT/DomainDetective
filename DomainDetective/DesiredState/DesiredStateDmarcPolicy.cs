using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDmarcPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the DMARC record to be syntactically valid (v=DMARC1 + p= tag, valid pct, valid report URIs).</summary>
    [JsonPropertyName("requireValidRecord")]
    public bool? RequireValidRecord { get; set; }

    /// <summary>When true, requires exactly one DMARC record to be published.</summary>
    [JsonPropertyName("requireSingleRecord")]
    public bool? RequireSingleRecord { get; set; }

    /// <summary>Allowed DMARC policy values (p= tag), as lowercase strings (none/quarantine/reject).</summary>
    [JsonPropertyName("allowedPolicies")]
    public string[]? AllowedPolicies { get; set; }

    /// <summary>Allowed DMARC subdomain policy values (sp= tag), as lowercase strings (none/quarantine/reject).</summary>
    [JsonPropertyName("allowedSubdomainPolicies")]
    public string[]? AllowedSubdomainPolicies { get; set; }

    /// <summary>When true, requires an explicit sp= tag to be present.</summary>
    [JsonPropertyName("requireSubdomainPolicyTag")]
    public bool? RequireSubdomainPolicyTag { get; set; }

    /// <summary>Allowed aspf values (r/s) as lowercase strings.</summary>
    [JsonPropertyName("allowedAspfAlignments")]
    public string[]? AllowedAspfAlignments { get; set; }

    /// <summary>Allowed adkim values (r/s) as lowercase strings.</summary>
    [JsonPropertyName("allowedAdkimAlignments")]
    public string[]? AllowedAdkimAlignments { get; set; }

    [JsonPropertyName("requireRua")]
    public bool? RequireRua { get; set; }

    /// <summary>When true, requires at least one mailto: rua address (not only HTTPS endpoints).</summary>
    [JsonPropertyName("requireMailtoRua")]
    public bool? RequireMailtoRua { get; set; }

    /// <summary>When true, disallows HTTPS endpoints in rua=.</summary>
    [JsonPropertyName("disallowHttpRua")]
    public bool? DisallowHttpRua { get; set; }

    /// <summary>When true, disallows DMARC forensic reporting (ruf=).</summary>
    [JsonPropertyName("disallowRuf")]
    public bool? DisallowRuf { get; set; }

    /// <summary>When true, disallows HTTPS endpoints in ruf=.</summary>
    [JsonPropertyName("disallowHttpRuf")]
    public bool? DisallowHttpRuf { get; set; }

    /// <summary>When true, disallows weak policy (p=none or sp=none).</summary>
    [JsonPropertyName("disallowWeakPolicy")]
    public bool? DisallowWeakPolicy { get; set; }

    /// <summary>When true, disallows DMARC records longer than 255 characters.</summary>
    [JsonPropertyName("disallowRecordOver255")]
    public bool? DisallowRecordOver255 { get; set; }

    /// <summary>When true, disallows unknown/unrecognized DMARC tags (helps detect typos).</summary>
    [JsonPropertyName("disallowUnknownTags")]
    public bool? DisallowUnknownTags { get; set; }

    /// <summary>When true, disallows deprecated DMARC tags (e.g., pct=, rf= per DMARCbis drafts).</summary>
    [JsonPropertyName("disallowDeprecatedTags")]
    public bool? DisallowDeprecatedTags { get; set; }

    /// <summary>Allowed domain suffixes for DMARC rua/ruf URIs (e.g., dmarc.vendor.example).</summary>
    [JsonPropertyName("allowedReportDomainSuffixes")]
    public string[]? AllowedReportDomainSuffixes { get; set; }

    /// <summary>When true, requires external reporting domains to be authorized via _report._dmarc.</summary>
    [JsonPropertyName("requireExternalReportAuthorization")]
    public bool? RequireExternalReportAuthorization { get; set; }

    public DesiredStateDmarcPolicy Clone() {
        return new DesiredStateDmarcPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValidRecord = RequireValidRecord,
            RequireSingleRecord = RequireSingleRecord,
            AllowedPolicies = AllowedPolicies?.ToArray(),
            AllowedSubdomainPolicies = AllowedSubdomainPolicies?.ToArray(),
            RequireSubdomainPolicyTag = RequireSubdomainPolicyTag,
            AllowedAspfAlignments = AllowedAspfAlignments?.ToArray(),
            AllowedAdkimAlignments = AllowedAdkimAlignments?.ToArray(),
            RequireRua = RequireRua,
            RequireMailtoRua = RequireMailtoRua,
            DisallowHttpRua = DisallowHttpRua,
            DisallowRuf = DisallowRuf,
            DisallowHttpRuf = DisallowHttpRuf,
            DisallowWeakPolicy = DisallowWeakPolicy,
            DisallowRecordOver255 = DisallowRecordOver255,
            DisallowUnknownTags = DisallowUnknownTags,
            DisallowDeprecatedTags = DisallowDeprecatedTags,
            AllowedReportDomainSuffixes = AllowedReportDomainSuffixes?.ToArray(),
            RequireExternalReportAuthorization = RequireExternalReportAuthorization
        };
    }

    public void Apply(DesiredStateDmarcPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValidRecord.HasValue) RequireValidRecord = overlay.RequireValidRecord;
        if (overlay.RequireSingleRecord.HasValue) RequireSingleRecord = overlay.RequireSingleRecord;
        if (overlay.AllowedPolicies != null) AllowedPolicies = overlay.AllowedPolicies.ToArray();
        if (overlay.AllowedSubdomainPolicies != null) AllowedSubdomainPolicies = overlay.AllowedSubdomainPolicies.ToArray();
        if (overlay.RequireSubdomainPolicyTag.HasValue) RequireSubdomainPolicyTag = overlay.RequireSubdomainPolicyTag;
        if (overlay.AllowedAspfAlignments != null) AllowedAspfAlignments = overlay.AllowedAspfAlignments.ToArray();
        if (overlay.AllowedAdkimAlignments != null) AllowedAdkimAlignments = overlay.AllowedAdkimAlignments.ToArray();
        if (overlay.RequireRua.HasValue) RequireRua = overlay.RequireRua;
        if (overlay.RequireMailtoRua.HasValue) RequireMailtoRua = overlay.RequireMailtoRua;
        if (overlay.DisallowHttpRua.HasValue) DisallowHttpRua = overlay.DisallowHttpRua;
        if (overlay.DisallowRuf.HasValue) DisallowRuf = overlay.DisallowRuf;
        if (overlay.DisallowHttpRuf.HasValue) DisallowHttpRuf = overlay.DisallowHttpRuf;
        if (overlay.DisallowWeakPolicy.HasValue) DisallowWeakPolicy = overlay.DisallowWeakPolicy;
        if (overlay.DisallowRecordOver255.HasValue) DisallowRecordOver255 = overlay.DisallowRecordOver255;
        if (overlay.DisallowUnknownTags.HasValue) DisallowUnknownTags = overlay.DisallowUnknownTags;
        if (overlay.DisallowDeprecatedTags.HasValue) DisallowDeprecatedTags = overlay.DisallowDeprecatedTags;
        if (overlay.AllowedReportDomainSuffixes != null) AllowedReportDomainSuffixes = overlay.AllowedReportDomainSuffixes.ToArray();
        if (overlay.RequireExternalReportAuthorization.HasValue) RequireExternalReportAuthorization = overlay.RequireExternalReportAuthorization;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireValidRecord ??= true;
        RequireSingleRecord ??= true;
        RequireRua ??= true;
        RequireMailtoRua ??= false;
        DisallowHttpRua ??= false;
        RequireExternalReportAuthorization ??= true;
        RequireSubdomainPolicyTag ??= false;
        DisallowRuf ??= false;
        DisallowHttpRuf ??= false;
        DisallowWeakPolicy ??= false;
        DisallowRecordOver255 ??= false;
        DisallowUnknownTags ??= false;
        DisallowDeprecatedTags ??= false;
    }
}
