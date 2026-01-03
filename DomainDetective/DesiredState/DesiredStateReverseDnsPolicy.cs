using System.Text.Json.Serialization;
using System.Linq;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateReverseDnsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no reverse DNS results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, requires each analyzed IP address to have at least one PTR record.</summary>
    [JsonPropertyName("requirePtrPresent")]
    public bool? RequirePtrPresent { get; set; }

    /// <summary>When true, requires at least one PTR record to match the expected host name.</summary>
    [JsonPropertyName("requirePtrMatchesExpectedHost")]
    public bool? RequirePtrMatchesExpectedHost { get; set; }

    /// <summary>Allowed PTR hostname suffixes (e.g., "mail.protection.outlook.com").</summary>
    [JsonPropertyName("allowedPtrSuffixes")]
    public string[]? AllowedPtrSuffixes { get; set; }

    /// <summary>When true, requires forward-confirmed reverse DNS (FCrDNS) for each IP.</summary>
    [JsonPropertyName("requireForwardConfirmed")]
    public bool? RequireForwardConfirmed { get; set; }

    public DesiredStateReverseDnsPolicy Clone() {
        return new DesiredStateReverseDnsPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequirePtrPresent = RequirePtrPresent,
            RequirePtrMatchesExpectedHost = RequirePtrMatchesExpectedHost,
            AllowedPtrSuffixes = AllowedPtrSuffixes?.ToArray(),
            RequireForwardConfirmed = RequireForwardConfirmed
        };
    }

    public void Apply(DesiredStateReverseDnsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequirePtrPresent.HasValue) RequirePtrPresent = overlay.RequirePtrPresent;
        if (overlay.RequirePtrMatchesExpectedHost.HasValue) RequirePtrMatchesExpectedHost = overlay.RequirePtrMatchesExpectedHost;
        if (overlay.AllowedPtrSuffixes != null) AllowedPtrSuffixes = overlay.AllowedPtrSuffixes.ToArray();
        if (overlay.RequireForwardConfirmed.HasValue) RequireForwardConfirmed = overlay.RequireForwardConfirmed;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequirePtrPresent ??= false;
        RequirePtrMatchesExpectedHost ??= false;
        RequireForwardConfirmed ??= false;
    }
}
