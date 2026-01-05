using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateDnsOverTlsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no DNS over TLS results were analyzed.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>When true, requires at least one authoritative server to support DNS over TLS.</summary>
    [JsonPropertyName("requireAnySupported")]
    public bool? RequireAnySupported { get; set; }

    /// <summary>When true, requires all probed authoritative servers to support DNS over TLS.</summary>
    [JsonPropertyName("requireAllSupported")]
    public bool? RequireAllSupported { get; set; }

    /// <summary>When true, requires supported servers to present a valid certificate chain.</summary>
    [JsonPropertyName("requireCertificateValid")]
    public bool? RequireCertificateValid { get; set; }

    /// <summary>When true, requires supported servers to present a certificate matching the name server hostname.</summary>
    [JsonPropertyName("requireHostnameMatch")]
    public bool? RequireHostnameMatch { get; set; }

    public DesiredStateDnsOverTlsPolicy Clone() {
        return new DesiredStateDnsOverTlsPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireAnySupported = RequireAnySupported,
            RequireAllSupported = RequireAllSupported,
            RequireCertificateValid = RequireCertificateValid,
            RequireHostnameMatch = RequireHostnameMatch
        };
    }

    public void Apply(DesiredStateDnsOverTlsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireAnySupported.HasValue) RequireAnySupported = overlay.RequireAnySupported;
        if (overlay.RequireAllSupported.HasValue) RequireAllSupported = overlay.RequireAllSupported;
        if (overlay.RequireCertificateValid.HasValue) RequireCertificateValid = overlay.RequireCertificateValid;
        if (overlay.RequireHostnameMatch.HasValue) RequireHostnameMatch = overlay.RequireHostnameMatch;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireAnySupported ??= false;
        RequireAllSupported ??= false;
        RequireCertificateValid ??= false;
        RequireHostnameMatch ??= false;
    }
}

