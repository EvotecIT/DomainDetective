using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static SecurityTxtInfo Convert(SecurityTXTAnalysis analysis)
    {
        var assessments = analysis.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        var narrative = DomainDetective.Narratives.SecurityTxtNarrative.Build(analysis);
        DateTimeOffset? expiresAt = null;
        int? daysUntilExpiry = null;
        if (!string.IsNullOrWhiteSpace(analysis.Expires) &&
            DateTimeOffset.TryParse(analysis.Expires, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var parsed))
        {
            expiresAt = parsed;
            daysUntilExpiry = (int)Math.Ceiling((parsed - DateTimeOffset.UtcNow).TotalDays);
        }

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
            ExpiresAt = expiresAt,
            DaysUntilExpiry = daysUntilExpiry,
            SignatureEncryption = analysis.SignatureEncryption,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"present {(analysis.RecordPresent ? "yes" : "no")}; signed {(analysis.PGPSigned ? "yes" : "no")}",
            Narrative = narrative,
            Highlights = narrative.Highlights,
            Details = narrative.Details,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(System.Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }
}

public class SecurityTxtInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = null!;
    public bool RecordPresent { get; set; }
    public bool RecordValid { get; set; }
    public bool PGPSigned { get; set; }
    public bool FallbackUsed { get; set; }
    public string Url { get; set; } = null!;
    public IReadOnlyCollection<string> DuplicateTags { get; set; } = null!;
    public IReadOnlyList<string> ContactEmail { get; set; } = null!;
    public IReadOnlyList<string> ContactWebsite { get; set; } = null!;
    public IReadOnlyList<string> Acknowledgments { get; set; } = null!;
    public IReadOnlyList<string> PreferredLanguages { get; set; } = null!;
    public IReadOnlyList<string> Encryption { get; set; } = null!;
    public IReadOnlyList<string> Policy { get; set; } = null!;
    public IReadOnlyList<string> Hiring { get; set; } = null!;
    public IReadOnlyList<string> Canonical { get; set; } = null!;
    public string Expires { get; set; } = null!;
    public DateTimeOffset? ExpiresAt { get; set; }
    public int? DaysUntilExpiry { get; set; }
    public string SignatureEncryption { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public DomainDetective.Narratives.SecurityTxtNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SecurityTxtNarrative.Sections();
    public IReadOnlyList<string> Highlights { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<string> Details { get; set; } = System.Array.Empty<string>();
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    [JsonIgnore]
    public SecurityTXTAnalysis Raw { get; set; } = null!;
}
