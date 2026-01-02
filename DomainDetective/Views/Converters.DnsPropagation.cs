using DnsClientX;
using System;
using System.Collections.Generic;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsPropagationInfo Convert(DnsPropagationReportAnalysis analysis)
    {
        if (analysis == null) throw new ArgumentNullException(nameof(analysis));

        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);

        string durationPart;
        try
        {
            var min = analysis.MinDuration;
            var max = analysis.MaxDuration;
            if (min.HasValue && max.HasValue)
            {
                durationPart = $"{min.Value.TotalMilliseconds:0}–{max.Value.TotalMilliseconds:0}ms";
            }
            else if (analysis.AvgDuration.HasValue)
            {
                durationPart = $"{analysis.AvgDuration.Value.TotalMilliseconds:0}ms";
            }
            else
            {
                durationPart = "-";
            }
        }
        catch
        {
            durationPart = "-";
        }

        var summary = $"{analysis.RecordType}; servers {analysis.ServerCount}; ok {analysis.SuccessCount}; err {analysis.ErrorCount}; sets {analysis.DistinctAnswerSets}; time {durationPart}{(analysis.ResultsCapped ? "; capped" : string.Empty)}";

        return new DnsPropagationInfo
        {
            Check = HealthCheckType.DNSPROPAGATION,
            Area = AreaForKind(HealthCheckType.DNSPROPAGATION),
            Subject = analysis.Subject,
            RecordType = analysis.RecordType,
            QuerySucceeded = analysis.QuerySucceeded,
            ServerCount = analysis.ServerCount,
            ServerSuccessCount = analysis.SuccessCount,
            ServerErrorCount = analysis.ErrorCount,
            DistinctAnswerSets = analysis.DistinctAnswerSets,
            MajorityAnswerSet = analysis.MajorityAnswerSet,
            MinDuration = analysis.MinDuration,
            MaxDuration = analysis.MaxDuration,
            AvgDuration = analysis.AvgDuration,
            ResultsCapped = analysis.ResultsCapped,
            Results = analysis.Results,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = summary,
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(analysis.References, recs),
            Raw = analysis
        };
    }
}

public sealed class DnsPropagationInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public DnsRecordType RecordType { get; set; }
    public bool QuerySucceeded { get; set; }
    public int ServerCount { get; set; }
    public int ServerSuccessCount { get; set; }
    public int ServerErrorCount { get; set; }
    public int DistinctAnswerSets { get; set; }
    public string? MajorityAnswerSet { get; set; }
    public TimeSpan? MinDuration { get; set; }
    public TimeSpan? MaxDuration { get; set; }
    public TimeSpan? AvgDuration { get; set; }
    public bool ResultsCapped { get; set; }
    public IReadOnlyList<DnsPropagationResult> Results { get; set; } = Array.Empty<DnsPropagationResult>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    public DnsPropagationReportAnalysis Raw { get; set; } = null!;
}
