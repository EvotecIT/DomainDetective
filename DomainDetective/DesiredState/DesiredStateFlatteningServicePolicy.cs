using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state flattening service policy functionality.</summary>
public sealed class DesiredStateFlatteningServicePolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, requires the apex to publish a CNAME record.</summary>
    [JsonPropertyName("requireCnameRecord")]
    public bool? RequireCnameRecord { get; set; }

    /// <summary>When true, disallows an apex CNAME record.</summary>
    [JsonPropertyName("disallowCnameRecord")]
    public bool? DisallowCnameRecord { get; set; }

    /// <summary>When true, requires the apex CNAME to point to a known flattening service.</summary>
    [JsonPropertyName("requireFlatteningService")]
    public bool? RequireFlatteningService { get; set; }

    /// <summary>When true, disallows the use of a known flattening service.</summary>
    [JsonPropertyName("disallowFlatteningService")]
    public bool? DisallowFlatteningService { get; set; }

    /// <summary>Allowed CNAME target suffixes (vendor-specific baselining).</summary>
    [JsonPropertyName("allowedTargetSuffixes")]
    public string[]? AllowedTargetSuffixes { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateFlatteningServicePolicy Clone() {
        return new DesiredStateFlatteningServicePolicy {
            Enabled = Enabled,
            RequireCnameRecord = RequireCnameRecord,
            DisallowCnameRecord = DisallowCnameRecord,
            RequireFlatteningService = RequireFlatteningService,
            DisallowFlatteningService = DisallowFlatteningService,
            AllowedTargetSuffixes = AllowedTargetSuffixes?.ToArray()
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateFlatteningServicePolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireCnameRecord.HasValue) RequireCnameRecord = overlay.RequireCnameRecord;
        if (overlay.DisallowCnameRecord.HasValue) DisallowCnameRecord = overlay.DisallowCnameRecord;
        if (overlay.RequireFlatteningService.HasValue) RequireFlatteningService = overlay.RequireFlatteningService;
        if (overlay.DisallowFlatteningService.HasValue) DisallowFlatteningService = overlay.DisallowFlatteningService;
        if (overlay.AllowedTargetSuffixes != null) AllowedTargetSuffixes = overlay.AllowedTargetSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireCnameRecord ??= false;
        DisallowCnameRecord ??= false;
        RequireFlatteningService ??= false;
        DisallowFlatteningService ??= false;
    }
}

