using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json.Serialization;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
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

    /// <summary>Executes the convert operation.</summary>
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

/// <summary>Provides dns propagation info functionality.</summary>
public sealed class DnsPropagationInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the record type value.</summary>
    public DnsRecordType RecordType { get; set; }
    /// <summary>Gets or sets the query succeeded value.</summary>
    public bool QuerySucceeded { get; set; }
    /// <summary>Gets or sets the server count value.</summary>
    public int ServerCount { get; set; }
    /// <summary>Gets or sets the server success count value.</summary>
    public int ServerSuccessCount { get; set; }
    /// <summary>Gets or sets the server error count value.</summary>
    public int ServerErrorCount { get; set; }
    /// <summary>Gets or sets the distinct answer sets value.</summary>
    public int DistinctAnswerSets { get; set; }
    /// <summary>Gets or sets the majority answer set value.</summary>
    public string? MajorityAnswerSet { get; set; }
    /// <summary>Gets or sets the min duration value.</summary>
    public TimeSpan? MinDuration { get; set; }
    /// <summary>Gets or sets the max duration value.</summary>
    public TimeSpan? MaxDuration { get; set; }
    /// <summary>Gets or sets the avg duration value.</summary>
    public TimeSpan? AvgDuration { get; set; }
    /// <summary>Gets or sets the results capped value.</summary>
    public bool ResultsCapped { get; set; }
    /// <summary>Gets or sets the results value.</summary>
    public IReadOnlyList<DnsPropagationResultInfo> Results { get; set; } = Array.Empty<DnsPropagationResultInfo>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public DnsPropagationReportAnalysis Raw { get; set; } = null!;
}

/// <summary>Provides dns propagation result info functionality.</summary>
public sealed class DnsPropagationResultInfo
{
    /// <summary>Gets or sets the server name value.</summary>
    public string ServerName { get; set; } = string.Empty;
    /// <summary>Gets or sets the server address value.</summary>
    public string ServerAddress { get; set; } = string.Empty;
    /// <summary>Gets or sets the country value.</summary>
    public string Country { get; set; } = string.Empty;
    /// <summary>Gets or sets the location value.</summary>
    public string Location { get; set; } = string.Empty;
    /// <summary>Gets or sets the asn value.</summary>
    public string Asn { get; set; } = string.Empty;
    /// <summary>Gets or sets the asn name value.</summary>
    public string AsnName { get; set; } = string.Empty;
    /// <summary>Gets or sets the record type value.</summary>
    public DnsRecordType RecordType { get; set; }
    /// <summary>Gets or sets the records value.</summary>
    public IReadOnlyList<string> Records { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the duration value.</summary>
    public TimeSpan Duration { get; set; }
    /// <summary>Gets or sets the success value.</summary>
    public bool Success { get; set; }
    /// <summary>Gets or sets the error value.</summary>
    public string Error { get; set; } = string.Empty;
}

/// <summary>Provides dns propagation set info functionality.</summary>
public sealed class DnsPropagationSetInfo
{
    /// <summary>Gets or sets the check value.</summary>
    public HealthCheckType Check { get; set; }
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Gets or sets the items value.</summary>
    public IReadOnlyList<DnsPropagationInfo> Items { get; set; } = Array.Empty<DnsPropagationInfo>();
    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = string.Empty;
    /// <summary>Gets or sets the warning count value.</summary>
    public int WarningCount { get; set; }
    /// <summary>Gets or sets the error count value.</summary>
    public int ErrorCount { get; set; }
    /// <summary>Gets or sets the summary value.</summary>
    public string Summary { get; set; } = string.Empty;
    /// <summary>Gets or sets the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the positives value.</summary>
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    /// <summary>Gets or sets the references value.</summary>
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();
    /// <summary>Gets or sets the raw value.</summary>
    [JsonIgnore]
    public DnsPropagationSetAnalysis Raw { get; set; } = null!;
}
