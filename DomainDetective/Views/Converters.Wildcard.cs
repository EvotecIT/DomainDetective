using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static WildcardDnsInfo Convert(WildcardDnsAnalysis analysis)
    {
        var assessments = (analysis as IHasAssessments)?.Assessments ?? new List<Assessment>();
        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);
        return new WildcardDnsInfo
        {
            Check = HealthCheckType.WILDCARDDNS,
            Area = AreaForKind(HealthCheckType.WILDCARDDNS),
            Subject = string.Empty,
            CatchAll = analysis.CatchAll,
            SoaExists = analysis.SoaExists,
            NsExists = analysis.NsExists,
            TestedNames = analysis.TestedNames,
            ResolvedNames = analysis.ResolvedNames,
            ResolvedAddresses = analysis.ResolvedAddresses,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = analysis.CatchAll ? "enabled" : "disabled",
            Recommendations = recs,
            Positives = positives,
            References = new [] { "https://www.rfc-editor.org/rfc/rfc4592" },
            Raw = analysis
        };
    }
}

/// <summary>Provides wildcard dns info functionality.</summary>
public class WildcardDnsInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;
    /// <summary>Gets or sets the catch all value.</summary>
    public bool CatchAll { get; set; }
    /// <summary>Gets or sets the soa exists value.</summary>
    public bool SoaExists { get; set; }
    /// <summary>Gets or sets the ns exists value.</summary>
    public bool NsExists { get; set; }
    /// <summary>Gets or sets the tested names value.</summary>
    public IReadOnlyList<string> TestedNames { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the resolved names value.</summary>
    public IReadOnlyList<string> ResolvedNames { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the resolved addresses value.</summary>
    public IReadOnlyList<string> ResolvedAddresses { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = System.Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = System.Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = System.Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    public WildcardDnsAnalysis Raw { get; set; } = new WildcardDnsAnalysis();
}
