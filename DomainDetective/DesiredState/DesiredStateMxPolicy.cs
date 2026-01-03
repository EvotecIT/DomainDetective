using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateMxPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("requireRecord")]
    public bool? RequireRecord { get; set; }

    [JsonPropertyName("requireNullMx")]
    public bool? RequireNullMx { get; set; }

    [JsonPropertyName("disallowNullMx")]
    public bool? DisallowNullMx { get; set; }

    [JsonPropertyName("requireBackupServers")]
    public bool? RequireBackupServers { get; set; }

    [JsonPropertyName("requireIpv6Supported")]
    public bool? RequireIpv6Supported { get; set; }

    /// <summary>Allowed host suffixes for MX targets (e.g., protection.outlook.com).</summary>
    [JsonPropertyName("allowedHostSuffixes")]
    public string[]? AllowedHostSuffixes { get; set; }

    [JsonPropertyName("disallowCnameTargets")]
    public bool? DisallowCnameTargets { get; set; }

    [JsonPropertyName("disallowIpTargets")]
    public bool? DisallowIpTargets { get; set; }

    [JsonPropertyName("disallowNonExistentTargets")]
    public bool? DisallowNonExistentTargets { get; set; }

    [JsonPropertyName("disallowNoAddressTargets")]
    public bool? DisallowNoAddressTargets { get; set; }

    [JsonPropertyName("disallowLocalhostTargets")]
    public bool? DisallowLocalhostTargets { get; set; }

    [JsonPropertyName("requireTtlUniform")]
    public bool? RequireTtlUniform { get; set; }

    [JsonPropertyName("requireRrsetConsistentAcrossNs")]
    public bool? RequireRrsetConsistentAcrossNs { get; set; }

    [JsonPropertyName("requireTargetAddressConsistentAcrossNs")]
    public bool? RequireTargetAddressConsistentAcrossNs { get; set; }

    public DesiredStateMxPolicy Clone() {
        return new DesiredStateMxPolicy {
            Enabled = Enabled,
            RequireRecord = RequireRecord,
            RequireNullMx = RequireNullMx,
            DisallowNullMx = DisallowNullMx,
            RequireBackupServers = RequireBackupServers,
            RequireIpv6Supported = RequireIpv6Supported,
            AllowedHostSuffixes = AllowedHostSuffixes?.ToArray(),
            DisallowCnameTargets = DisallowCnameTargets,
            DisallowIpTargets = DisallowIpTargets,
            DisallowNonExistentTargets = DisallowNonExistentTargets,
            DisallowNoAddressTargets = DisallowNoAddressTargets,
            DisallowLocalhostTargets = DisallowLocalhostTargets,
            RequireTtlUniform = RequireTtlUniform,
            RequireRrsetConsistentAcrossNs = RequireRrsetConsistentAcrossNs,
            RequireTargetAddressConsistentAcrossNs = RequireTargetAddressConsistentAcrossNs
        };
    }

    public void Apply(DesiredStateMxPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireRecord.HasValue) RequireRecord = overlay.RequireRecord;
        if (overlay.RequireNullMx.HasValue) RequireNullMx = overlay.RequireNullMx;
        if (overlay.DisallowNullMx.HasValue) DisallowNullMx = overlay.DisallowNullMx;
        if (overlay.RequireBackupServers.HasValue) RequireBackupServers = overlay.RequireBackupServers;
        if (overlay.RequireIpv6Supported.HasValue) RequireIpv6Supported = overlay.RequireIpv6Supported;
        if (overlay.AllowedHostSuffixes != null) AllowedHostSuffixes = overlay.AllowedHostSuffixes.ToArray();
        if (overlay.DisallowCnameTargets.HasValue) DisallowCnameTargets = overlay.DisallowCnameTargets;
        if (overlay.DisallowIpTargets.HasValue) DisallowIpTargets = overlay.DisallowIpTargets;
        if (overlay.DisallowNonExistentTargets.HasValue) DisallowNonExistentTargets = overlay.DisallowNonExistentTargets;
        if (overlay.DisallowNoAddressTargets.HasValue) DisallowNoAddressTargets = overlay.DisallowNoAddressTargets;
        if (overlay.DisallowLocalhostTargets.HasValue) DisallowLocalhostTargets = overlay.DisallowLocalhostTargets;
        if (overlay.RequireTtlUniform.HasValue) RequireTtlUniform = overlay.RequireTtlUniform;
        if (overlay.RequireRrsetConsistentAcrossNs.HasValue) RequireRrsetConsistentAcrossNs = overlay.RequireRrsetConsistentAcrossNs;
        if (overlay.RequireTargetAddressConsistentAcrossNs.HasValue) RequireTargetAddressConsistentAcrossNs = overlay.RequireTargetAddressConsistentAcrossNs;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireRecord ??= true;
        RequireNullMx ??= false;
        DisallowNullMx ??= false;
        RequireBackupServers ??= false;
        RequireIpv6Supported ??= false;
        DisallowCnameTargets ??= true;
        DisallowIpTargets ??= true;
        DisallowNonExistentTargets ??= true;
        DisallowNoAddressTargets ??= true;
        DisallowLocalhostTargets ??= true;
        RequireTtlUniform ??= false;
        RequireRrsetConsistentAcrossNs ??= false;
        RequireTargetAddressConsistentAcrossNs ??= false;
    }
}
