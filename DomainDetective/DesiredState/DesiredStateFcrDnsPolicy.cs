using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state fcr dns policy functionality.</summary>
public sealed class DesiredStateFcrDnsPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no FCrDNS results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, requires all IPs to be forward-confirmed.</summary>
    [JsonPropertyName("requireAllForwardConfirmed")]
    public bool? RequireAllForwardConfirmed { get; set; }

    /// <summary>Executes the clone operation.</summary>
    public DesiredStateFcrDnsPolicy Clone() {
        return new DesiredStateFcrDnsPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireAllForwardConfirmed = RequireAllForwardConfirmed
        };
    }

    /// <summary>Executes the apply operation.</summary>
    public void Apply(DesiredStateFcrDnsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireAllForwardConfirmed.HasValue) RequireAllForwardConfirmed = overlay.RequireAllForwardConfirmed;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireAllForwardConfirmed ??= false;
    }
}
