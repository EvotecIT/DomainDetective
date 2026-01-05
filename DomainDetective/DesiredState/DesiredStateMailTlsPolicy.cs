using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

public sealed class DesiredStateMailTlsPolicy {
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no TLS results were produced.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    [JsonPropertyName("requireCertificateValid")]
    public bool? RequireCertificateValid { get; set; }

    [JsonPropertyName("requireChainValid")]
    public bool? RequireChainValid { get; set; }

    [JsonPropertyName("requireHostnameMatch")]
    public bool? RequireHostnameMatch { get; set; }

    [JsonPropertyName("disallowExpiredCertificates")]
    public bool? DisallowExpiredCertificates { get; set; }

    [JsonPropertyName("minCertificateDaysToExpire")]
    public int? MinCertificateDaysToExpire { get; set; }

    [JsonPropertyName("disallowLegacyProtocols")]
    public bool? DisallowLegacyProtocols { get; set; }

    [JsonPropertyName("minimumGradeLevel")]
    public GradeLevel? MinimumGradeLevel { get; set; }

    public DesiredStateMailTlsPolicy Clone() {
        return new DesiredStateMailTlsPolicy {
            Enabled = Enabled,
            RequireAtLeastOneResult = RequireAtLeastOneResult,
            RequireCertificateValid = RequireCertificateValid,
            RequireChainValid = RequireChainValid,
            RequireHostnameMatch = RequireHostnameMatch,
            DisallowExpiredCertificates = DisallowExpiredCertificates,
            MinCertificateDaysToExpire = MinCertificateDaysToExpire,
            DisallowLegacyProtocols = DisallowLegacyProtocols,
            MinimumGradeLevel = MinimumGradeLevel
        };
    }

    public void Apply(DesiredStateMailTlsPolicy overlay) {
        if (overlay == null) return;
        if (overlay.Enabled.HasValue) Enabled = overlay.Enabled;
        if (overlay.RequireAtLeastOneResult.HasValue) RequireAtLeastOneResult = overlay.RequireAtLeastOneResult;
        if (overlay.RequireCertificateValid.HasValue) RequireCertificateValid = overlay.RequireCertificateValid;
        if (overlay.RequireChainValid.HasValue) RequireChainValid = overlay.RequireChainValid;
        if (overlay.RequireHostnameMatch.HasValue) RequireHostnameMatch = overlay.RequireHostnameMatch;
        if (overlay.DisallowExpiredCertificates.HasValue) DisallowExpiredCertificates = overlay.DisallowExpiredCertificates;
        if (overlay.MinCertificateDaysToExpire.HasValue) MinCertificateDaysToExpire = overlay.MinCertificateDaysToExpire;
        if (overlay.DisallowLegacyProtocols.HasValue) DisallowLegacyProtocols = overlay.DisallowLegacyProtocols;
        if (overlay.MinimumGradeLevel.HasValue) MinimumGradeLevel = overlay.MinimumGradeLevel;
    }

    internal void NormalizeDefaults() {
        Enabled ??= true;
        RequireAtLeastOneResult ??= false;
        RequireCertificateValid ??= true;
        RequireChainValid ??= true;
        RequireHostnameMatch ??= true;
        DisallowExpiredCertificates ??= true;
        DisallowLegacyProtocols ??= true;
        MinimumGradeLevel ??= GradeLevel.B;
    }
}
