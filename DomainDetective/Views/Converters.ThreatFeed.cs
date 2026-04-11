using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static ThreatFeedInfo Convert(ThreatFeedAnalysis analysis)
    {
        var hasAssess = (analysis as IHasAssessments) != null;
        var assessments = hasAssess ? ((IHasAssessments)analysis).Assessments : new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = hasAssess ? RecommendationEngine.FromProblems(assessments) : new List<RecommendationAdvice>();
        var positives = hasAssess ? RecommendationEngine.FromPositives(assessments) : new List<RecommendationAdvice>();
        var listings = analysis.Listings?.Select(l => new ThreatListing { Source = l.Source.ToString(), Listed = l.IsListed }).ToList() ?? new List<ThreatListing>();
        return new ThreatFeedInfo
        {
            Check = HealthCheckType.THREATFEED,
            Subject = analysis.Subject,
            Listings = listings,
            FailureReason = analysis.FailureReason,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.virustotal.com/", "https://www.abuseipdb.com/" },
            Raw = analysis
        };
    }
}

/// <summary>Provides threat feed info functionality.</summary>
public class ThreatFeedInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the listings value.</summary>
    public IReadOnlyList<ThreatListing> Listings { get; set; } = null!;
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = null!;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public ThreatFeedAnalysis Raw { get; set; } = null!;
}

