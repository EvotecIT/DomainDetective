using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state wildcard dns policy functionality.</summary>
public sealed class DesiredStateWildcardDnsPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>
    /// Expected wildcard (catch-all) behavior. When null, no constraint is enforced.
    /// </summary>
    [JsonPropertyName("expectedCatchAll")]
    public bool? ExpectedCatchAll { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateWildcardDnsPolicy Clone() {
        return new DesiredStateWildcardDnsPolicy {
            Enabled = Enabled,
            ExpectedCatchAll = ExpectedCatchAll
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateWildcardDnsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.ExpectedCatchAll.HasValue) ExpectedCatchAll = overlay.ExpectedCatchAll;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}
