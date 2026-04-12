using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters {
    /// <summary>Executes the convert operation.</summary>
    public static CertificateInfo Convert(CertificateAnalysis analysis) {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var narrative = DomainDetective.Narratives.CertificateHttpNarrative.Build(analysis, analysis.Assessments);
        return new CertificateInfo {
            Check = HealthCheckType.CERT,
            Area = AreaForKind(HealthCheckType.CERT),
            Subject = analysis.Subject,
            Url = analysis.Url ?? analysis.Subject,
            IsReachable = analysis.IsReachable,
            FailureReason = analysis.FailureReason,
            FailureKind = analysis.FailureKind.ToString(),
            IsValid = analysis.IsValid,
            HostnameMatch = analysis.HostnameMatch,
            DaysToExpire = analysis.DaysToExpire,
            DaysValid = analysis.DaysValid,
            IsExpired = analysis.IsExpired,
            Grade = analysis.GradeLevel,
            ProtocolVersion = analysis.ProtocolVersion?.ToString(),
            Http2Supported = analysis.Http2Supported,
            Http3Supported = analysis.Http3Supported,
            SupportsTls10 = analysis.SupportsTls10,
            SupportsTls11 = analysis.SupportsTls11,
            SupportsTls12 = analysis.SupportsTls12,
            SupportsTls13 = analysis.SupportsTls13,
            TlsProtocol = analysis.TlsProtocol.ToString(),
            CipherAlgorithm = analysis.CipherAlgorithm,
            CipherStrength = analysis.CipherStrength,
            CipherSuite = analysis.CipherSuite,
            DhKeyBits = analysis.DhKeyBits,
            SctCount = analysis.SctCount,
            OcspMustStaple = analysis.OcspMustStaple,
            OcspStaplingPresent = analysis.OcspStaplingPresent,
            OcspUrls = analysis.OcspUrls,
            CrlUrls = analysis.CrlUrls,
            OcspRevoked = analysis.OcspRevoked,
            CrlRevoked = analysis.CrlRevoked,
            SubjectAlternativeNames = analysis.SubjectAlternativeNames,
            IsWildcardCertificate = analysis.IsWildcardCertificate,
            SecuresUnrelatedHosts = analysis.SecuresUnrelatedHosts,
            IsSelfSigned = analysis.IsSelfSigned,
            ChainLength = analysis.Chain.Count,
            ChainSource = analysis.ChainSource,
            ChainSourceHistory = analysis.ChainSourceHistory,
            CertificateSubject = analysis.Certificate?.Subject,
            CertificateIssuer = analysis.Certificate?.Issuer,
            ValidFrom = analysis.Certificate?.NotBefore,
            ValidTo = analysis.Certificate?.NotAfter,
            KeyAlgorithm = analysis.KeyAlgorithm,
            KeySize = analysis.KeySize,
            WeakKey = analysis.WeakKey,
            Sha1Signature = analysis.Sha1Signature,
            RsaPssSignature = analysis.RsaPssSignature,
            HasEnhancedKeyUsageExtension = analysis.HasEnhancedKeyUsageExtension,
            HasAnyExtendedKeyUsageOid = analysis.HasAnyExtendedKeyUsageOid,
            AllowsServerAuthentication = analysis.AllowsServerAuthentication,
            AllowsClientAuthentication = analysis.AllowsClientAuthentication,
            AllowsSecureEmail = analysis.AllowsSecureEmail,
            AuthenticationProfile = analysis.AuthenticationProfile,
            ExtendedKeyUsageOids = analysis.ExtendedKeyUsageOids,
            ExtendedKeyUsageFriendlyNames = analysis.ExtendedKeyUsageFriendlyNames,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{(analysis.IsValid ? "valid" : "invalid")}; host {(analysis.HostnameMatch ? "match" : "mismatch")}; expires {analysis.DaysToExpire}d; grade {analysis.GradeLevel.ToLetter()}; {analysis.KeyAlgorithm} {analysis.KeySize}b",
            Narrative = narrative,
            Highlights = narrative.Highlights,
            Details = narrative.Details,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs)
                .Concat(narrative.References ?? new List<string>())
                .Distinct(System.StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            Raw = analysis
        };
    }
}

/// <summary>Provides certificate info functionality.</summary>
public class CertificateInfo {
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the url value.</summary>
    public string? Url { get; set; }
    /// <summary>Gets or sets the is reachable value.</summary>
    public bool IsReachable { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the failure kind value.</summary>
    public string FailureKind { get; set; } = string.Empty;
    /// <summary>Gets or sets the is valid value.</summary>
    public bool IsValid { get; set; }
    /// <summary>Gets or sets the hostname match value.</summary>
    public bool HostnameMatch { get; set; }
    /// <summary>Gets or sets the days to expire value.</summary>
    public int DaysToExpire { get; set; }
    /// <summary>Gets or sets the days valid value.</summary>
    public int DaysValid { get; set; }
    /// <summary>Gets or sets the is expired value.</summary>
    public bool IsExpired { get; set; }
    /// <summary>Gets or sets the grade value.</summary>
    public GradeLevel Grade { get; set; }
    /// <summary>Gets or sets the protocol version value.</summary>
    public string? ProtocolVersion { get; set; }
    /// <summary>Gets or sets the http2 supported value.</summary>
    public bool Http2Supported { get; set; }
    /// <summary>Gets or sets the http3 supported value.</summary>
    public bool Http3Supported { get; set; }
    /// <summary>Gets or sets the supports tls10 value.</summary>
    public bool SupportsTls10 { get; set; }
    /// <summary>Gets or sets the supports tls11 value.</summary>
    public bool SupportsTls11 { get; set; }
    /// <summary>Gets or sets the supports tls12 value.</summary>
    public bool SupportsTls12 { get; set; }
    /// <summary>Gets or sets the supports tls13 value.</summary>
    public bool SupportsTls13 { get; set; }
    /// <summary>Gets or sets the tls protocol value.</summary>
    public string TlsProtocol { get; set; } = string.Empty;
    /// <summary>Gets or sets the cipher algorithm value.</summary>
    public string CipherAlgorithm { get; set; } = string.Empty;
    /// <summary>Gets or sets the cipher strength value.</summary>
    public int CipherStrength { get; set; }
    /// <summary>Gets or sets the cipher suite value.</summary>
    public string CipherSuite { get; set; } = string.Empty;
    /// <summary>Gets or sets the dh key bits value.</summary>
    public int DhKeyBits { get; set; }
    /// <summary>Gets or sets the sct count value.</summary>
    public int SctCount { get; set; }
    /// <summary>Gets or sets the ocsp must staple value.</summary>
    public bool OcspMustStaple { get; set; }
    /// <summary>Gets or sets the ocsp stapling present value.</summary>
    public bool? OcspStaplingPresent { get; set; }
    /// <summary>Gets or sets the ocsp urls value.</summary>
    public IReadOnlyList<string> OcspUrls { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the crl urls value.</summary>
    public IReadOnlyList<string> CrlUrls { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the ocsp revoked value.</summary>
    public bool? OcspRevoked { get; set; }
    /// <summary>Gets or sets the crl revoked value.</summary>
    public bool? CrlRevoked { get; set; }
    /// <summary>Gets or sets the subject alternative names value.</summary>
    public IReadOnlyList<string> SubjectAlternativeNames { get; set; } = null!;
    /// <summary>Gets or sets the is wildcard certificate value.</summary>
    public bool IsWildcardCertificate { get; set; }
    /// <summary>Gets or sets the secures unrelated hosts value.</summary>
    public bool SecuresUnrelatedHosts { get; set; }
    /// <summary>Gets or sets the is self signed value.</summary>
    public bool IsSelfSigned { get; set; }
    /// <summary>Gets or sets the chain length value.</summary>
    public int ChainLength { get; set; }
    /// <summary>Gets or sets the chain source value.</summary>
    public string ChainSource { get; set; } = string.Empty;
    /// <summary>Gets or sets the chain source history value.</summary>
    public IReadOnlyList<string> ChainSourceHistory { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the certificate subject value.</summary>
    public string? CertificateSubject { get; set; }
    /// <summary>Gets or sets the certificate issuer value.</summary>
    public string? CertificateIssuer { get; set; }
    /// <summary>Gets or sets the valid from value.</summary>
    public System.DateTime? ValidFrom { get; set; }
    /// <summary>Gets or sets the valid to value.</summary>
    public System.DateTime? ValidTo { get; set; }
    /// <summary>Gets or sets the key algorithm value.</summary>
    public string KeyAlgorithm { get; set; } = null!;
    /// <summary>Gets or sets the key size value.</summary>
    public int KeySize { get; set; }
    /// <summary>Gets or sets the weak key value.</summary>
    public bool WeakKey { get; set; }
    /// <summary>Gets or sets the sha1 signature value.</summary>
    public bool Sha1Signature { get; set; }
    /// <summary>Gets or sets the rsa pss signature value.</summary>
    public bool RsaPssSignature { get; set; }
    /// <summary>Gets or sets the has enhanced key usage extension value.</summary>
    public bool HasEnhancedKeyUsageExtension { get; set; }
    /// <summary>Gets or sets the has any extended key usage oid value.</summary>
    public bool HasAnyExtendedKeyUsageOid { get; set; }
    /// <summary>Gets or sets the allows server authentication value.</summary>
    public bool AllowsServerAuthentication { get; set; }
    /// <summary>Gets or sets the allows client authentication value.</summary>
    public bool AllowsClientAuthentication { get; set; }
    /// <summary>Gets or sets the allows secure email value.</summary>
    public bool AllowsSecureEmail { get; set; }
    /// <summary>Gets or sets the authentication profile value.</summary>
    public string AuthenticationProfile { get; set; } = string.Empty;
    /// <summary>Gets or sets the extended key usage oids value.</summary>
    public IReadOnlyList<string> ExtendedKeyUsageOids { get; set; } = null!;
    /// <summary>Gets or sets the extended key usage friendly names value.</summary>
    public IReadOnlyList<string> ExtendedKeyUsageFriendlyNames { get; set; } = null!;
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the narrative value.</summary>
    public DomainDetective.Narratives.CertificateHttpNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.CertificateHttpNarrative.Sections();
    /// <summary>Gets or sets the highlights value.</summary>
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the details value.</summary>
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public CertificateAnalysis Raw { get; set; } = null!;
}
