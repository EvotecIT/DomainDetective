using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>
/// Desired state policy for certificate inventory posture evaluation.
/// </summary>
public sealed class DesiredStateCertificateInventoryPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    [JsonPropertyName("baselineProfile")]
    public string? BaselineProfile { get; set; }

    [JsonPropertyName("includeCompliant")]
    public bool? IncludeCompliant { get; set; }

    [JsonPropertyName("maxEndpoints")]
    public int? MaxEndpoints { get; set; }

    [JsonPropertyName("policyOverridesPath")]
    public string? PolicyOverridesPath { get; set; }

    public DesiredStateCertificateInventoryPolicy Clone() {
        return new DesiredStateCertificateInventoryPolicy {
            Enabled = Enabled,
            BaselineProfile = BaselineProfile,
            IncludeCompliant = IncludeCompliant,
            MaxEndpoints = MaxEndpoints,
            PolicyOverridesPath = PolicyOverridesPath
        };
    }

    public void Apply(DesiredStateCertificateInventoryPolicy? overlay) {
        if (overlay == null) {
            return;
        }

        if (overlay.Enabled.HasValue) {
            Enabled = overlay.Enabled;
        }

        if (!string.IsNullOrWhiteSpace(overlay.BaselineProfile)) {
            BaselineProfile = overlay.BaselineProfile;
        }

        if (overlay.IncludeCompliant.HasValue) {
            IncludeCompliant = overlay.IncludeCompliant;
        }

        if (overlay.MaxEndpoints.HasValue) {
            MaxEndpoints = overlay.MaxEndpoints;
        }

        if (overlay.PolicyOverridesPath != null) {
            PolicyOverridesPath = overlay.PolicyOverridesPath;
        }
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        IncludeCompliant ??= false;
        MaxEndpoints ??= 300;
        if (MaxEndpoints.HasValue && MaxEndpoints.Value < 0) {
            MaxEndpoints = 300;
        }

        if (!CertificateInventoryPolicyAnalyzer.TryResolveBaselineProfile(BaselineProfile, out var normalizedProfile)) {
            normalizedProfile = "Balanced";
        }

        BaselineProfile = normalizedProfile;

        string? policyOverridesPath = PolicyOverridesPath;
        if (string.IsNullOrWhiteSpace(policyOverridesPath)) {
            PolicyOverridesPath = null;
        } else {
            PolicyOverridesPath = policyOverridesPath!.Trim();
        }
    }
}
