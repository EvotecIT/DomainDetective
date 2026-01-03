using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateRpkiPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no RPKI results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, invalid (non-ignored) results are treated as drift.</summary>
    [JsonPropertyName("disallowInvalid")]
    public bool? DisallowInvalid { get; set; }

    /// <summary>
    /// When true, failed RPKI lookups (no prefix/ASN information) are treated as drift.
    /// When false, lookup failures are ignored for desired state purposes.
    /// </summary>
    [JsonPropertyName("treatQueryFailuresAsDrift")]
    public bool? TreatQueryFailuresAsDrift { get; set; }

    /// <summary>Optional allow-list of IP addresses to ignore.</summary>
    [JsonPropertyName("ignoredIpAddresses")]
    public string[]? IgnoredIpAddresses { get; set; }

    /// <summary>Optional allow-list of prefixes to ignore (as returned by the provider).</summary>
    [JsonPropertyName("ignoredPrefixes")]
    public string[]? IgnoredPrefixes { get; set; }

    /// <summary>Optional allow-list of ASNs to ignore.</summary>
    [JsonPropertyName("ignoredAsns")]
    public int[]? IgnoredAsns { get; set; }

    public DesiredStateRpkiPolicy Clone() {
        return new DesiredStateRpkiPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowInvalid = DisallowInvalid,
            TreatQueryFailuresAsDrift = TreatQueryFailuresAsDrift,
            IgnoredIpAddresses = IgnoredIpAddresses?.ToArray(),
            IgnoredPrefixes = IgnoredPrefixes?.ToArray(),
            IgnoredAsns = IgnoredAsns?.ToArray()
        };
    }

    public void Apply(DesiredStateRpkiPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.DisallowInvalid.HasValue) DisallowInvalid = overlay.DisallowInvalid;
        if (overlay.TreatQueryFailuresAsDrift.HasValue) TreatQueryFailuresAsDrift = overlay.TreatQueryFailuresAsDrift;
        if (overlay.IgnoredIpAddresses != null) IgnoredIpAddresses = overlay.IgnoredIpAddresses.ToArray();
        if (overlay.IgnoredPrefixes != null) IgnoredPrefixes = overlay.IgnoredPrefixes.ToArray();
        if (overlay.IgnoredAsns != null) IgnoredAsns = overlay.IgnoredAsns.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        DisallowInvalid ??= true;
        TreatQueryFailuresAsDrift ??= false;
    }
}

