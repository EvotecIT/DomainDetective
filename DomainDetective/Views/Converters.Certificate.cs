using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters {
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

public class CertificateInfo {
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public string? Url { get; set; }
    public bool IsReachable { get; set; }
    public string? FailureReason { get; set; }
    public string FailureKind { get; set; } = string.Empty;
    public bool IsValid { get; set; }
    public bool HostnameMatch { get; set; }
    public int DaysToExpire { get; set; }
    public int DaysValid { get; set; }
    public bool IsExpired { get; set; }
    public GradeLevel Grade { get; set; }
    public string? ProtocolVersion { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public bool SupportsTls10 { get; set; }
    public bool SupportsTls11 { get; set; }
    public bool SupportsTls12 { get; set; }
    public bool SupportsTls13 { get; set; }
    public string TlsProtocol { get; set; } = string.Empty;
    public string CipherAlgorithm { get; set; } = string.Empty;
    public int CipherStrength { get; set; }
    public string CipherSuite { get; set; } = string.Empty;
    public int DhKeyBits { get; set; }
    public int SctCount { get; set; }
    public bool OcspMustStaple { get; set; }
    public bool? OcspStaplingPresent { get; set; }
    public IReadOnlyList<string> OcspUrls { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> CrlUrls { get; set; } = System.Array.Empty<string>();
    public bool? OcspRevoked { get; set; }
    public bool? CrlRevoked { get; set; }
    public IReadOnlyList<string> SubjectAlternativeNames { get; set; } = null!;
    public bool IsWildcardCertificate { get; set; }
    public bool SecuresUnrelatedHosts { get; set; }
    public bool IsSelfSigned { get; set; }
    public int ChainLength { get; set; }
    public string ChainSource { get; set; } = string.Empty;
    public IReadOnlyList<string> ChainSourceHistory { get; set; } = System.Array.Empty<string>();
    public string? CertificateSubject { get; set; }
    public string? CertificateIssuer { get; set; }
    public System.DateTime? ValidFrom { get; set; }
    public System.DateTime? ValidTo { get; set; }
    public string KeyAlgorithm { get; set; } = null!;
    public int KeySize { get; set; }
    public bool WeakKey { get; set; }
    public bool Sha1Signature { get; set; }
    public bool RsaPssSignature { get; set; }
    public bool HasEnhancedKeyUsageExtension { get; set; }
    public bool HasAnyExtendedKeyUsageOid { get; set; }
    public bool AllowsServerAuthentication { get; set; }
    public bool AllowsClientAuthentication { get; set; }
    public bool AllowsSecureEmail { get; set; }
    public string AuthenticationProfile { get; set; } = string.Empty;
    public IReadOnlyList<string> ExtendedKeyUsageOids { get; set; } = null!;
    public IReadOnlyList<string> ExtendedKeyUsageFriendlyNames { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public DomainDetective.Narratives.CertificateHttpNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.CertificateHttpNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    [JsonIgnore]
    public CertificateAnalysis Raw { get; set; } = null!;
}
