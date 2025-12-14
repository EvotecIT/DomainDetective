using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public class ThreatFeedInfo
{
    public HealthCheckType Check { get; set; }
    public string? Subject { get; set; }
    public IReadOnlyList<ThreatListing> Listings { get; set; } = null!;
    public string? FailureReason { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public ThreatFeedAnalysis Raw { get; set; } = null!;
}

