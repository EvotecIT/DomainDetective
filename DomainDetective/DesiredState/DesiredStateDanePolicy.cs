using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDanePolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireValidRecords")]
    public bool? RequireValidRecords { get; set; }

    [JsonPropertyName("disallowDuplicates")]
    public bool? DisallowDuplicates { get; set; }

    [JsonPropertyName("requiredServices")]
    public ServiceType[]? RequiredServices { get; set; }

    [JsonPropertyName("requireRecommendedForSmtp")]
    public bool? RequireRecommendedForSmtp { get; set; }

    [JsonPropertyName("requireRecommendedForHttps")]
    public bool? RequireRecommendedForHttps { get; set; }

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
