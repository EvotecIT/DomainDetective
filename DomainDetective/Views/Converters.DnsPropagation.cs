using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DnsPropagationSetInfo Convert(DnsPropagationSetAnalysis analysis)
    {
        if (analysis == null) throw new ArgumentNullException(nameof(analysis));

        Summarize(analysis.Assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(analysis.Assessments);
        var positives = RecommendationEngine.FromPositives(analysis.Assessments);
        var items = analysis.Items.Select(Convert).ToArray();

        return new DnsPropagationSetInfo
        {
            Check = HealthCheckType.DNSPROPAGATION,
            Area = AreaForKind(HealthCheckType.DNSPROPAGATION),
            Subject = analysis.Subject,
            Items = items,
            Assessments = analysis.Assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = $"reports {items.Length}; consistent {items.Count(static item => item.DistinctAnswerSets <= 1)}; warnings {warnCount}; errors {errCount}",
            Recommendations = recs,
            Positives = positives,
            References = BuildReferences(Array.Empty<StandardReference>(), recs),
            Raw = analysis
        };
    }

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
            Results = analysis.Results.Select(ConvertPropagationResult).ToArray(),
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

    private static DnsPropagationResultInfo ConvertPropagationResult(DnsPropagationResult result)
    {
        return new DnsPropagationResultInfo
        {
            ServerName = result.Server?.HostName ?? string.Empty,
            ServerAddress = result.Server?.IPAddress?.ToString() ?? string.Empty,
            Country = result.Server?.Country is { } country ? country.ToName() : string.Empty,
            Location = result.Server?.Location is { } location ? location.ToName() : string.Empty,
            Asn = result.Server?.ASN ?? string.Empty,
            AsnName = result.Server?.ASNName ?? string.Empty,
            RecordType = result.RecordType,
            Records = result.Records?.ToArray() ?? Array.Empty<string>(),
            Duration = result.Duration,
            Success = result.Success,
            Error = result.Error ?? string.Empty
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
    public IReadOnlyList<DnsPropagationResultInfo> Results { get; set; } = Array.Empty<DnsPropagationResultInfo>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    [JsonIgnore]
    public DnsPropagationReportAnalysis Raw { get; set; } = null!;
}

public sealed class DnsPropagationResultInfo
{
    public string ServerName { get; set; } = string.Empty;
    public string ServerAddress { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string Location { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public string AsnName { get; set; } = string.Empty;
    public DnsRecordType RecordType { get; set; }
    public IReadOnlyList<string> Records { get; set; } = Array.Empty<string>();
    public TimeSpan Duration { get; set; }
    public bool Success { get; set; }
    public string Error { get; set; } = string.Empty;
}

public sealed class DnsPropagationSetInfo
{
    public HealthCheckType Check { get; set; }
    public AnalysisArea Area { get; set; }
    public string? Subject { get; set; }
    public IReadOnlyList<DnsPropagationInfo> Items { get; set; } = Array.Empty<DnsPropagationInfo>();
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public string Status { get; set; } = string.Empty;
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    [JsonIgnore]
    public DnsPropagationSetAnalysis Raw { get; set; } = null!;
}
