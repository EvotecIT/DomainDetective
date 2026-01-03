using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateNsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireAtLeastTwo")]
    public bool? RequireAtLeastTwo { get; set; }

    [JsonPropertyName("disallowDuplicates")]
    public bool? DisallowDuplicates { get; set; }

    [JsonPropertyName("requireAllHaveAOrAaaa")]
    public bool? RequireAllHaveAOrAaaa { get; set; }

    [JsonPropertyName("disallowCnameTargets")]
    public bool? DisallowCnameTargets { get; set; }

    [JsonPropertyName("requireDiversity")]
    public bool? RequireDiversity { get; set; }

    /// <summary>Minimum distinct ASN count for authoritative name servers.</summary>
    [JsonPropertyName("minAsnDiversity")]
    public int? MinAsnDiversity { get; set; }

    /// <summary>Allowed host suffixes for authoritative NS targets (e.g., ns.provider.example).</summary>
    [JsonPropertyName("allowedHostSuffixes")]
    public string[]? AllowedHostSuffixes { get; set; }

    public DesiredStateNsPolicy Clone() {
        return new DesiredStateNsPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireAtLeastTwo = RequireAtLeastTwo,
            DisallowDuplicates = DisallowDuplicates,
            RequireAllHaveAOrAaaa = RequireAllHaveAOrAaaa,
            DisallowCnameTargets = DisallowCnameTargets,
            RequireDiversity = RequireDiversity,
            MinAsnDiversity = MinAsnDiversity,
            AllowedHostSuffixes = AllowedHostSuffixes?.ToArray()
        };
    }

    public void Apply(DesiredStateNsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireAtLeastTwo.HasValue) RequireAtLeastTwo = overlay.RequireAtLeastTwo;
        if (overlay.DisallowDuplicates.HasValue) DisallowDuplicates = overlay.DisallowDuplicates;
        if (overlay.RequireAllHaveAOrAaaa.HasValue) RequireAllHaveAOrAaaa = overlay.RequireAllHaveAOrAaaa;
        if (overlay.DisallowCnameTargets.HasValue) DisallowCnameTargets = overlay.DisallowCnameTargets;
        if (overlay.RequireDiversity.HasValue) RequireDiversity = overlay.RequireDiversity;
        if (overlay.MinAsnDiversity.HasValue) MinAsnDiversity = overlay.MinAsnDiversity;
        if (overlay.AllowedHostSuffixes != null) AllowedHostSuffixes = overlay.AllowedHostSuffixes.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireAtLeastTwo ??= true;
        DisallowDuplicates ??= true;
        RequireAllHaveAOrAaaa ??= true;
        DisallowCnameTargets ??= true;
        RequireDiversity ??= false;
    }
}
