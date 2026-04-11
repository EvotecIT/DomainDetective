using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static IpEnrichmentInfo Convert(IpEnrichmentAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        return new IpEnrichmentInfo
        {
            Check = HealthCheckType.IPENRICHMENT,
            Area = AreaForKind(HealthCheckType.IPENRICHMENT),
            Subject = analysis.Subject,
            QuerySucceeded = analysis.QuerySucceeded,
            ResultsCapped = analysis.ResultsCapped,
            FailureReason = analysis.FailureReason,
            UniqueIpCount = analysis.UniqueIpCount,
            RowCount = analysis.RowCount,
            DistinctAsnCount = analysis.DistinctAsnCount,
            DistinctCountryCount = analysis.DistinctCountryCount,
            AsnCounts = analysis.AsnCounts,
            CountryCounts = analysis.CountryCounts,
            Rows = analysis.Rows,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"IPs {analysis.UniqueIpCount}; rows {analysis.RowCount}; ASNs {analysis.DistinctAsnCount}; countries {analysis.DistinctCountryCount}; capped {(analysis.ResultsCapped ? "yes" : "no")}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.References, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides ip enrichment info functionality.</summary>
public sealed class IpEnrichmentInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; set; }
    /// <summary>Gets or sets the results capped value.</summary>
    public bool ResultsCapped { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the unique ip count value.</summary>
    public int UniqueIpCount { get; set; }
    /// <summary>Gets or sets the row count value.</summary>
    public int RowCount { get; set; }
    /// <summary>Gets or sets the distinct asn count value.</summary>
    public int DistinctAsnCount { get; set; }
    /// <summary>Gets or sets the distinct country count value.</summary>
    public int DistinctCountryCount { get; set; }
    /// <summary>Gets or sets the asn counts value.</summary>
    public IReadOnlyDictionary<int, int> AsnCounts { get; set; } = null!;
    /// <summary>Gets or sets the country counts value.</summary>
    public IReadOnlyDictionary<string, int> CountryCounts { get; set; } = null!;
    /// <summary>Gets or sets the rows value.</summary>
    public IReadOnlyList<IpEnrichmentRow> Rows { get; set; } = null!;
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
    public IpEnrichmentAnalysis Raw { get; set; } = null!;
}

