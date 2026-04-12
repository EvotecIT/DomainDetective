using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state ns policy functionality.</summary>
public sealed class DesiredStateNsPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>Gets or sets the require record value.</summary>
    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    /// <summary>Gets or sets the require at least two value.</summary>
    [JsonPropertyName("requireAtLeastTwo")]
    public bool? RequireAtLeastTwo { get; set; }

    /// <summary>Gets or sets the disallow duplicates value.</summary>
    [JsonPropertyName("disallowDuplicates")]
    public bool? DisallowDuplicates { get; set; }

    /// <summary>Gets or sets the require all have a or aaaa value.</summary>
    [JsonPropertyName("requireAllHaveAOrAaaa")]
    public bool? RequireAllHaveAOrAaaa { get; set; }

    /// <summary>Gets or sets the disallow cname targets value.</summary>
    [JsonPropertyName("disallowCnameTargets")]
    public bool? DisallowCnameTargets { get; set; }

    /// <summary>Gets or sets the require diversity value.</summary>
    [JsonPropertyName("requireDiversity")]
    public bool? RequireDiversity { get; set; }

    /// <summary>Minimum distinct ASN count for authoritative name servers.</summary>
    [JsonPropertyName("minAsnDiversity")]
    public int? MinAsnDiversity { get; set; }

    /// <summary>Allowed host suffixes for authoritative NS targets (e.g., ns.provider.example).</summary>
    [JsonPropertyName("allowedHostSuffixes")]
    public string[]? AllowedHostSuffixes { get; set; }

    /// <summary>Executes the clone operation.</summary>
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

    /// <summary>Executes the apply operation.</summary>
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
