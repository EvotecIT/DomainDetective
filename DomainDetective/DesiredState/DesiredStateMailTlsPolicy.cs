using System.Text.Json.Serialization;

namespace DomainDetective.DesiredState;

/// <summary>Provides desired state mail tls policy functionality.</summary>
public sealed class DesiredStateMailTlsPolicy {
    /// <summary>Gets or sets the enabled value.</summary>
    [JsonPropertyName("enabled")]
    public bool? Enabled { get; set; }

    /// <summary>When true, warns if no TLS results were produced.</summary>
    [JsonPropertyName("requireAtLeastOneResult")]
    public bool? RequireAtLeastOneResult { get; set; }

    /// <summary>Gets or sets the require certificate valid value.</summary>
    [JsonPropertyName("requireCertificateValid")]
    public bool? RequireCertificateValid { get; set; }

    /// <summary>Gets or sets the require chain valid value.</summary>
    [JsonPropertyName("requireChainValid")]
    public bool? RequireChainValid { get; set; }

    /// <summary>Gets or sets the require hostname match value.</summary>
    [JsonPropertyName("requireHostnameMatch")]
    public bool? RequireHostnameMatch { get; set; }

    /// <summary>Gets or sets the disallow expired certificates value.</summary>
    [JsonPropertyName("disallowExpiredCertificates")]
    public bool? DisallowExpiredCertificates { get; set; }

    /// <summary>Gets or sets the min certificate days to expire value.</summary>
    [JsonPropertyName("minCertificateDaysToExpire")]
    public int? MinCertificateDaysToExpire { get; set; }

    /// <summary>Gets or sets the disallow legacy protocols value.</summary>
    [JsonPropertyName("disallowLegacyProtocols")]
    public bool? DisallowLegacyProtocols { get; set; }

    /// <summary>Gets or sets the minimum grade level value.</summary>
    [JsonPropertyName("minimumGradeLevel")]
    public GradeLevel? MinimumGradeLevel { get; set; }

    /// <summary>Executes the clone operation.</summary>
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

    /// <summary>Executes the apply operation.</summary>
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
