using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static ThreatIntelInfo Convert(ThreatIntelAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var findings = analysis.Listings?.Select(l => new ThreatListing { Source = l.Source.ToString(), Listed = l.IsListed }).ToList() ?? new List<ThreatListing>();
        var flagged = findings.Count(f => f.Listed);
        return new ThreatIntelInfo
        {
            Check = HealthCheckType.THREATINTEL,
            Area = AreaForKind(HealthCheckType.THREATINTEL),
            Subject = analysis.Subject,
            RiskScore = analysis.RiskScore,
            CompositeScore = analysis.CompositeScore,
            Severity = analysis.Severity,
            Confidence = analysis.Confidence,
            Listings = findings,
            FailureReason = analysis.FailureReason,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"Flagged by {flagged}/{findings.Count} providers; score {analysis.CompositeScore?.ToString() ?? "n/a"} ({analysis.Severity ?? "n/a"})",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://developers.google.com/safe-browsing", "https://www.virustotal.com/", "https://www.phishtank.com/", "https://urlhaus.abuse.ch/api/" },
            Raw = analysis
        };
    }
}

/// <summary>Provides threat intel info functionality.</summary>
public class ThreatIntelInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the risk score value.</summary>
    public int? RiskScore { get; set; }
    /// <summary>Gets or sets the composite score value.</summary>
    public int? CompositeScore { get; set; }
    /// <summary>Gets or sets the severity value.</summary>
    public string? Severity { get; set; }
    /// <summary>Gets or sets the confidence value.</summary>
    public double? Confidence { get; set; }
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
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = null!;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = null!;
    /// <summary>Gets or sets the raw value.</summary>
    public ThreatIntelAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides threat listing functionality.</summary>
public class ThreatListing
{
    /// <summary>Gets or sets the source value.</summary>
    public string Source { get; set; } = null!;
    /// <summary>Gets or sets the listed value.</summary>
    public bool Listed { get; set; }
}

