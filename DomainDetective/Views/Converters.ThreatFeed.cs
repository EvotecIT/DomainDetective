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
        var recs = hasAssess ? RecommendationEngine.From(assessments) : new List<RecommendationAdvice>();
        var listings = analysis.Listings?.Select(l => new ThreatListing { Source = l.Source.ToString(), Listed = l.IsListed }).ToList() ?? new List<ThreatListing>();
        return new ThreatFeedInfo
        {
            Check = "THREATFEED",
            Subject = analysis.Subject,
            Listings = listings,
            FailureReason = analysis.FailureReason,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Recommendations = recs,
            References = new [] { "https://www.virustotal.com/", "https://www.abuseipdb.com/" },
            Raw = analysis
        };
    }
}

public class ThreatFeedInfo
{
    public string Check { get; set; }
    public string Subject { get; set; }
    public IReadOnlyList<ThreatListing> Listings { get; set; }
    public string FailureReason { get; set; }
    public IReadOnlyList<Assessment> Assessments { get; set; }
    public string Status { get; set; }
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; }
    public IReadOnlyList<string> References { get; set; }
    public ThreatFeedAnalysis Raw { get; set; }
}

