using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static DnsTraceInfo Convert(DnsTraceAnalysis analysis)
    {
        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        var refs = new[]
        {
            new StandardReference { Title = "Domain Name System", Reference = "RFC 1035", Url = "https://www.rfc-editor.org/rfc/rfc1035" }
        };

        var summary = $"{analysis.TotalSteps} step(s); queries {analysis.TraceQueries}; failed {analysis.TraceQueriesFailed}; ipv6 roots {(analysis.IncludeIpv6RootServers ? "on" : "off")}; depth {analysis.MaxDepth}; cap {analysis.MaxTotalSteps}";

        return new DnsTraceInfo
        {
            Check = HealthCheckType.DNSTRACE,
            Area = AreaForKind(HealthCheckType.DNSTRACE),
            Subject = analysis.Subject,
            TraceSucceeded = analysis.TraceSucceeded,
            FailureReason = analysis.FailureReason,
            TraceQueries = analysis.TraceQueries,
            TraceQueriesFailed = analysis.TraceQueriesFailed,
            TotalSteps = analysis.TotalSteps,
            Queries = analysis.Queries ?? Array.Empty<DnsTraceQuery>(),
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(refs, recs),
            Raw = analysis
        };
    }
}

/// <summary>Provides dns trace info functionality.</summary>
public sealed class DnsTraceInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the trace succeeded value.</summary>
    public bool TraceSucceeded { get; set; }
    /// <summary>Gets or sets the failure reason value.</summary>
    public string? FailureReason { get; set; }
    /// <summary>Gets or sets the trace queries value.</summary>
    public int TraceQueries { get; set; }
    /// <summary>Gets or sets the trace queries failed value.</summary>
    public int TraceQueriesFailed { get; set; }
    /// <summary>Gets or sets the total steps value.</summary>
    public int TotalSteps { get; set; }
    /// <summary>Gets or sets the queries value.</summary>
    public IReadOnlyList<DnsTraceQuery> Queries { get; set; } = null!;
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
    public DnsTraceAnalysis Raw { get; set; } = null!;
}

