using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
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

public sealed class DnsTraceInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public bool TraceSucceeded { get; set; }
    public string? FailureReason { get; set; }
    public int TraceQueries { get; set; }
    public int TraceQueriesFailed { get; set; }
    public int TotalSteps { get; set; }
    public IReadOnlyList<DnsTraceQuery> Queries { get; set; } = null!;
    public IReadOnlyList<Assessment> Assessments { get; set; } = null!;
    public string Status { get; set; } = null!;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = null!;
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = null!;
    public IReadOnlyList<string> References { get; set; } = null!;
    public DnsTraceAnalysis Raw { get; set; } = null!;
}

