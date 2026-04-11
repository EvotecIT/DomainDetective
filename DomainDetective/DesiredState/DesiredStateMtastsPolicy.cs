using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state mtasts policy functionality.</summary>
public sealed class DesiredStateMtastsPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>When true, requires the _mta-sts TXT record to be syntactically valid (v=STSv1; id=...).</summary>
    [JsonPropertyName("requireDnsRecordValid")]
    public bool? RequireDnsRecordValid { get; set; }

    /// <summary>When true, requires the HTTPS policy file to be fetched successfully.</summary>
    [JsonPropertyName("requirePolicyPresent")]
    public bool? RequirePolicyPresent { get; set; }

    /// <summary>When true, requires the HTTPS policy file to be valid and consistent with the DNS bootstrap record.</summary>
    [JsonPropertyName("requirePolicyValid")]
    public bool? RequirePolicyValid { get; set; }

    /// <summary>When true, disallows duplicate fields in either the DNS record or the policy file.</summary>
    [JsonPropertyName("disallowDuplicateFields")]
    public bool? DisallowDuplicateFields { get; set; }

    /// <summary>Gets or sets the require enforce value.</summary>
    [JsonPropertyName("requireEnforce")]
    public bool? RequireEnforce { get; set; }

    /// <summary>Minimum accepted max_age value (seconds).</summary>
    [JsonPropertyName("minMaxAge")]
    public int? MinMaxAge { get; set; }

    /// <summary>Gets or sets the require mx aligned value.</summary>
    [JsonPropertyName("requireMxAligned")]
    public bool? RequireMxAligned { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateMtastsPolicy Clone() {
        return new DesiredStateMtastsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireDnsRecordValid = RequireDnsRecordValid,
            RequirePolicyPresent = RequirePolicyPresent,
            RequirePolicyValid = RequirePolicyValid,
            DisallowDuplicateFields = DisallowDuplicateFields,
            RequireEnforce = RequireEnforce,
            MinMaxAge = MinMaxAge,
            RequireMxAligned = RequireMxAligned
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateMtastsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireDnsRecordValid.HasValue) RequireDnsRecordValid = overlay.RequireDnsRecordValid;
        if (overlay.RequirePolicyPresent.HasValue) RequirePolicyPresent = overlay.RequirePolicyPresent;
        if (overlay.RequirePolicyValid.HasValue) RequirePolicyValid = overlay.RequirePolicyValid;
        if (overlay.DisallowDuplicateFields.HasValue) DisallowDuplicateFields = overlay.DisallowDuplicateFields;
        if (overlay.RequireEnforce.HasValue) RequireEnforce = overlay.RequireEnforce;
        if (overlay.MinMaxAge.HasValue) MinMaxAge = overlay.MinMaxAge;
        if (overlay.RequireMxAligned.HasValue) RequireMxAligned = overlay.RequireMxAligned;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireDnsRecordValid ??= false;
        RequirePolicyPresent ??= false;
        RequirePolicyValid ??= false;
        DisallowDuplicateFields ??= false;
    }
}
