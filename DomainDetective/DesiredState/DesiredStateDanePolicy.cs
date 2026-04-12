using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state dane policy functionality.</summary>
public sealed class DesiredStateDanePolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Gets or sets the require valid records value.</summary>
    [JsonPropertyName("requireValidRecords")]
    public bool? RequireValidRecords { get; set; }

    /// <summary>Gets or sets the disallow duplicates value.</summary>
    [JsonPropertyName("disallowDuplicates")]
    public bool? DisallowDuplicates { get; set; }

    /// <summary>Gets or sets the required services value.</summary>
    [JsonPropertyName("requiredServices")]
    public ServiceType[]? RequiredServices { get; set; }

    /// <summary>Gets or sets the require recommended for smtp value.</summary>
    [JsonPropertyName("requireRecommendedForSmtp")]
    public bool? RequireRecommendedForSmtp { get; set; }

    /// <summary>Gets or sets the require recommended for https value.</summary>
    [JsonPropertyName("requireRecommendedForHttps")]
    public bool? RequireRecommendedForHttps { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDanePolicy Clone() {
        return new DesiredStateDanePolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireValidRecords = RequireValidRecords,
            DisallowDuplicates = DisallowDuplicates,
            RequiredServices = RequiredServices?.ToArray(),
            RequireRecommendedForSmtp = RequireRecommendedForSmtp,
            RequireRecommendedForHttps = RequireRecommendedForHttps
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateDanePolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireValidRecords.HasValue) RequireValidRecords = overlay.RequireValidRecords;
        if (overlay.DisallowDuplicates.HasValue) DisallowDuplicates = overlay.DisallowDuplicates;
        if (overlay.RequiredServices != null) RequiredServices = overlay.RequiredServices.ToArray();
        if (overlay.RequireRecommendedForSmtp.HasValue) RequireRecommendedForSmtp = overlay.RequireRecommendedForSmtp;
        if (overlay.RequireRecommendedForHttps.HasValue) RequireRecommendedForHttps = overlay.RequireRecommendedForHttps;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= false;
        RequireValidRecords ??= true;
        DisallowDuplicates ??= false;
    }
}
