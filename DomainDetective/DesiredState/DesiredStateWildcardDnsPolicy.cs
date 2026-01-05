using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateWildcardDnsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>
    /// Expected wildcard (catch-all) behavior. When null, no constraint is enforced.
    /// </summary>
    [JsonPropertyName("expectedCatchAll")]
    public bool? ExpectedCatchAll { get; set; }

    public DesiredStateWildcardDnsPolicy Clone() {
        return new DesiredStateWildcardDnsPolicy {
            Enabled = Enabled,
            ExpectedCatchAll = ExpectedCatchAll
        };
    }

    public void Apply(DesiredStateWildcardDnsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.ExpectedCatchAll.HasValue) ExpectedCatchAll = overlay.ExpectedCatchAll;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
    }
}
