using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides security txt info functionality.</summary>
public class SecurityTxtInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = null!;
    /// <summary>Gets or sets the record present value.</summary>
    public bool RecordPresent { get; set; }
    /// <summary>Gets or sets the record valid value.</summary>
    public bool RecordValid { get; set; }
    /// <summary>Gets or sets the pgp signed value.</summary>
    public bool PGPSigned { get; set; }
    /// <summary>Gets or sets the fallback used value.</summary>
    public bool FallbackUsed { get; set; }
    /// <summary>Gets or sets the url value.</summary>
    public string Url { get; set; } = null!;
    /// <summary>Gets or sets the duplicate tags value.</summary>
    public IReadOnlyCollection<string> DuplicateTags { get; set; } = null!;
    /// <summary>Gets or sets the contact email value.</summary>
    public IReadOnlyList<string> ContactEmail { get; set; } = null!;
    /// <summary>Gets or sets the contact website value.</summary>
    public IReadOnlyList<string> ContactWebsite { get; set; } = null!;
    /// <summary>Gets or sets the acknowledgments value.</summary>
    public IReadOnlyList<string> Acknowledgments { get; set; } = null!;
    /// <summary>Gets or sets the preferred languages value.</summary>
    public IReadOnlyList<string> PreferredLanguages { get; set; } = null!;
    /// <summary>Gets or sets the encryption value.</summary>
    public IReadOnlyList<string> Encryption { get; set; } = null!;
    /// <summary>Gets or sets the policy value.</summary>
    public IReadOnlyList<string> Policy { get; set; } = null!;
    /// <summary>Gets or sets the hiring value.</summary>
    public IReadOnlyList<string> Hiring { get; set; } = null!;
    /// <summary>Gets or sets the canonical value.</summary>
    public IReadOnlyList<string> Canonical { get; set; } = null!;
    /// <summary>Gets or sets the expires value.</summary>
    public string Expires { get; set; } = null!;
    /// <summary>Gets or sets the expires at value.</summary>
    public DateTimeOffset? ExpiresAt { get; set; }
    /// <summary>Gets or sets the days until expiry value.</summary>
    public int? DaysUntilExpiry { get; set; }
    /// <summary>Gets or sets the signature encryption value.</summary>
    public string SignatureEncryption { get; set; } = null!;
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
    public DomainDetective.Narratives.SecurityTxtNarrative.Sections Narrative { get; set; } = new DomainDetective.Narratives.SecurityTxtNarrative.Sections();
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
    public SecurityTXTAnalysis Raw { get; set; } = null!;
}
