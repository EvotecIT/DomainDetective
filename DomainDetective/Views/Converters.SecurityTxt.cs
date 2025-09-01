using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SecurityTxtInfo Convert(SecurityTXTAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.From(assessments);
        return new SecurityTxtInfo
        {
            Check = HealthCheckType.SECURITYTXT,
            Area = AreaForKind(HealthCheckType.SECURITYTXT),
            Subject = analysis.Domain,
            RecordPresent = analysis.RecordPresent,
            RecordValid = analysis.RecordValid,
            PGPSigned = analysis.PGPSigned,
            FallbackUsed = analysis.FallbackUsed,
            Url = analysis.Url,
            DuplicateTags = analysis.DuplicateTags,
            ContactEmail = analysis.ContactEmail,
            ContactWebsite = analysis.ContactWebsite,
            Acknowledgments = analysis.Acknowledgments,
            PreferredLanguages = analysis.PreferredLanguages,
            Encryption = analysis.Encryption,
            Policy = analysis.Policy,
            Hiring = analysis.Hiring,
            Canonical = analysis.Canonical,
            Expires = analysis.Expires,
            SignatureEncryption = analysis.SignatureEncryption,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"present {(analysis.RecordPresent ? "yes" : "no")}; signed {(analysis.PGPSigned ? "yes" : "no")}",
            Recommendations = recs,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class SecurityTxtInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; }
    public bool RecordPresent { get; set; }
    public bool RecordValid { get; set; }
    public bool PGPSigned { get; set; }
    public bool FallbackUsed { get; set; }
    public string Url { get; set; }
    public IReadOnlyCollection<string> DuplicateTags { get; set; }
    public IReadOnlyList<string> ContactEmail { get; set; }
    public IReadOnlyList<string> ContactWebsite { get; set; }
    public IReadOnlyList<string> Acknowledgments { get; set; }
    public IReadOnlyList<string> PreferredLanguages { get; set; }
    public IReadOnlyList<string> Encryption { get; set; }
    public IReadOnlyList<string> Policy { get; set; }
    public IReadOnlyList<string> Hiring { get; set; }
    public IReadOnlyList<string> Canonical { get; set; }
    public string Expires { get; set; }
    public string SignatureEncryption { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public SecurityTXTAnalysis Raw { get; set; }
}
