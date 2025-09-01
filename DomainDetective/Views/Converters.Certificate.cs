using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters {
    public static CertificateInfo Convert(CertificateAnalysis analysis) {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(analysis.Assessments);
        return new CertificateInfo {
            Check = "CERT",
            Area = AreaFor("CERT"),
            Subject = analysis.Subject,
            Url = analysis.Url ?? analysis.Subject,
            IsReachable = analysis.IsReachable,
            IsValid = analysis.IsValid,
            HostnameMatch = analysis.HostnameMatch,
            DaysToExpire = analysis.DaysToExpire,
            DaysValid = analysis.DaysValid,
            IsExpired = analysis.IsExpired,
            Grade = analysis.GradeLevel,
            Http2Supported = analysis.Http2Supported,
            Http3Supported = analysis.Http3Supported,
            SupportsTls10 = analysis.SupportsTls10,
            SupportsTls11 = analysis.SupportsTls11,
            SupportsTls12 = analysis.SupportsTls12,
            SupportsTls13 = analysis.SupportsTls13,
            SctCount = analysis.SctCount,
            OcspMustStaple = analysis.OcspMustStaple,
            OcspStaplingPresent = analysis.OcspStaplingPresent,
            SubjectAlternativeNames = analysis.SubjectAlternativeNames,
            IsWildcardCertificate = analysis.IsWildcardCertificate,
            IsSelfSigned = analysis.IsSelfSigned,
            KeyAlgorithm = analysis.KeyAlgorithm,
            KeySize = analysis.KeySize,
            WeakKey = analysis.WeakKey,
            Sha1Signature = analysis.Sha1Signature,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"{(analysis.IsValid ? "valid" : "invalid")}; host {(analysis.HostnameMatch ? "match" : "mismatch")}; expires {analysis.DaysToExpire}d; grade {analysis.GradeLevel.ToLetter()}; {analysis.KeyAlgorithm} {analysis.KeySize}b",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class CertificateInfo {
    public string Check { get; set; }
    public string Area { get; set; }
    public string Subject { get; set; }
    public string Url { get; set; }
    public bool IsReachable { get; set; }
    public bool IsValid { get; set; }
    public bool HostnameMatch { get; set; }
    public int DaysToExpire { get; set; }
    public int DaysValid { get; set; }
    public bool IsExpired { get; set; }
    public GradeLevel Grade { get; set; }
    public bool Http2Supported { get; set; }
    public bool Http3Supported { get; set; }
    public bool SupportsTls10 { get; set; }
    public bool SupportsTls11 { get; set; }
    public bool SupportsTls12 { get; set; }
    public bool SupportsTls13 { get; set; }
    public int SctCount { get; set; }
    public bool OcspMustStaple { get; set; }
    public bool? OcspStaplingPresent { get; set; }
    public IReadOnlyList<string> SubjectAlternativeNames { get; set; }
    public bool IsWildcardCertificate { get; set; }
    public bool IsSelfSigned { get; set; }
    public string KeyAlgorithm { get; set; }
    public int KeySize { get; set; }
    public bool WeakKey { get; set; }
    public bool Sha1Signature { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public CertificateAnalysis Raw { get; set; }
}
