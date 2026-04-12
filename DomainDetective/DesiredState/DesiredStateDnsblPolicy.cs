using System.Text.Json.Serialization;
using System.Linq;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state dnsbl policy functionality.</summary>
public sealed class DesiredStateDnsblPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no DNSBL results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, non-ignored listings are treated as drift.</summary>
    [JsonPropertyName("disallowListings")]
    public bool? DisallowListings { get; set; }

    /// <summary>Blacklist domains to ignore (e.g., some providers produce false positives).</summary>
    [JsonPropertyName("ignoredBlacklists")]
    public string[]? IgnoredBlacklists { get; set; }

    /// <summary>Optional allow-list of query kinds to evaluate (Domain/IpAddressV4/IpAddressV6).</summary>
    [JsonPropertyName("includeQueryKinds")]
    public DnsblQueryKind[]? IncludeQueryKinds { get; set; }

    /// <summary>Optional allow-list of IP sources to evaluate (MxA/MxAAAA/ApexA/ApexAAAA/Domain).</summary>
    [JsonPropertyName("includeIpSources")]
    public DnsblIpSource[]? IncludeIpSources { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateDnsblPolicy Clone() {
        return new DesiredStateDnsblPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            DisallowListings = DisallowListings,
            IgnoredBlacklists = IgnoredBlacklists?.ToArray(),
            IncludeQueryKinds = IncludeQueryKinds?.ToArray(),
            IncludeIpSources = IncludeIpSources?.ToArray()
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateDnsblPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.DisallowListings.HasValue) DisallowListings = overlay.DisallowListings;
        if (overlay.IgnoredBlacklists != null) IgnoredBlacklists = overlay.IgnoredBlacklists.ToArray();
        if (overlay.IncludeQueryKinds != null) IncludeQueryKinds = overlay.IncludeQueryKinds.ToArray();
        if (overlay.IncludeIpSources != null) IncludeIpSources = overlay.IncludeIpSources.ToArray();
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        DisallowListings ??= true;
    }
}
