using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.TimeSeries.TlsRpt;

namespace DomainDetective.Views;

public static partial class Converters
{
    /// <summary>Executes the convert operation.</summary>
    public static TlsRptReportsTimeSeriesInfo Convert(IReadOnlyList<TlsRptSnapshot> snapshots, string? subjectOverride = null)
    {
        var list = (snapshots ?? Array.Empty<TlsRptSnapshot>()).Where(s => s != null).ToList();
        var subject = !string.IsNullOrWhiteSpace(subjectOverride)
            ? subjectOverride!
            : (list.FirstOrDefault()?.Domain ?? string.Empty);

        var assessments = new List<Assessment>();

        int ok = list.Sum(s => s.TotalSuccessfulSessions);
        int fail = list.Sum(s => s.TotalFailedSessions);
        int total = ok + fail;
        double failRate = total > 0 ? (fail * 100.0 / total) : 0.0;

        DateTimeOffset? start = list.Count > 0
            ? list.Min(s => s.RangeBeginUtc ?? s.RangeEndUtc ?? s.IngestedAtUtc)
            : null;
        DateTimeOffset? end = list.Count > 0
            ? list.Max(s => s.RangeEndUtc ?? s.RangeBeginUtc ?? s.IngestedAtUtc)
            : null;

        if (list.Count == 0)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "TLSRPT.Reports.NoData",
                Category = "TLS-RPT",
                Target = subject,
                Message = "No TLS-RPT reports were found for this domain."
            });
        }
        else if (total <= 0)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "TLSRPT.Reports.ZeroSessions",
                Category = "TLS-RPT",
                Target = subject,
                Message = "TLS-RPT reports were ingested, but session count is zero."
            });
        }
        else if (fail > 0)
        {
            var sev = failRate >= 10.0 ? AssessmentSeverity.Error : AssessmentSeverity.Warning;
            assessments.Add(new Assessment
            {
                Severity = sev,
                Code = "TLSRPT.Reports.Failures",
                Category = "TLS-RPT",
                Target = subject,
                Message = $"TLS-RPT reports show {fail} failed sessions ({failRate:0.0}% failure rate)."
            });
        }
        else
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Code = "TLSRPT.Reports.AllSuccess",
                Category = "TLS-RPT",
                Target = subject,
                Message = "TLS-RPT reports show 0 failed sessions for observed deliveries."
            });
        }

        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);

        return new TlsRptReportsTimeSeriesInfo
        {
            SectionKey = "TLS-RPT Reports",
            Area = AreaForKind(HealthCheckType.TLSRPT),
            Subject = subject,
            PeriodStartUtc = start,
            PeriodEndUtc = end,
            SnapshotCount = list.Count,
            TotalSuccessfulSessions = ok,
            TotalFailedSessions = fail,
            FailureRatePercent = failRate,
            Daily = BuildDaily(list),
            TopFailureTypes = AggregateFailureTypes(list),
            MxHosts = AggregateMxHosts(list),
            Snapshots = list,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = total > 0
                ? $"reports {list.Count}; ok {ok}/{total}; fail {fail} ({failRate:0.0}%)"
                : $"reports {list.Count}; no session count",
            Recommendations = recs,
            Positives = positives,
            References = new[] { "https://www.rfc-editor.org/rfc/rfc8460" }
        };
    }

    private static List<TlsRptDailyStat> BuildDaily(List<TlsRptSnapshot> snaps)
    {
        var list = new List<TlsRptDailyStat>();
        if (snaps == null || snaps.Count == 0) return list;

        var grouped = snaps
            .GroupBy(s => (s.RangeEndUtc ?? s.IngestedAtUtc).UtcDateTime.Date)
            .OrderBy(g => g.Key);

        foreach (var g in grouped)
        {
            int ok = g.Sum(x => x.TotalSuccessfulSessions);
            int fail = g.Sum(x => x.TotalFailedSessions);
            int total = ok + fail;
            double failRate = total > 0 ? (fail * 100.0 / total) : 0.0;

            list.Add(new TlsRptDailyStat
            {
                DateUtc = g.Key,
                SuccessfulSessions = ok,
                FailedSessions = fail,
                FailureRatePercent = failRate
            });
        }

        return list;
    }

    private static IReadOnlyList<NamedCount> AggregateFailureTypes(List<TlsRptSnapshot> snaps)
    {
        var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in snaps ?? new List<TlsRptSnapshot>())
        {
            foreach (var kv in s.FailureTypeCounts ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value <= 0) continue;
                dict[kv.Key] = (dict.TryGetValue(kv.Key, out var prev) ? prev : 0) + kv.Value;
            }
        }

        return dict
            .Select(kv => new NamedCount { Key = kv.Key, Count = kv.Value })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();
    }

    private static IReadOnlyList<TlsRptMxHostStat> AggregateMxHosts(List<TlsRptSnapshot> snaps)
    {
        var map = new Dictionary<string, TlsRptMxHostStat>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in snaps ?? new List<TlsRptSnapshot>())
        {
            foreach (var mx in s.MxHosts ?? new List<TlsRptMxSnapshot>())
            {
                if (mx == null || string.IsNullOrWhiteSpace(mx.MxHost)) continue;
                if (!map.TryGetValue(mx.MxHost, out var row))
                {
                    row = new TlsRptMxHostStat { MxHost = mx.MxHost };
                    map[mx.MxHost] = row;
                }

                row.SuccessfulSessions += mx.SuccessfulSessions;
                row.FailedSessions += mx.FailedSessions;
                foreach (var kv in mx.FailureByType ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrWhiteSpace(kv.Key) || kv.Value <= 0) continue;
                    row.FailureByType[kv.Key] = (row.FailureByType.TryGetValue(kv.Key, out var prev) ? prev : 0) + kv.Value;
                }
            }
        }

        return map.Values
            .OrderByDescending(x => x.FailedSessions)
            .ThenBy(x => x.MxHost, StringComparer.OrdinalIgnoreCase)
            .Take(25)
            .ToList();
    }
}

/// <summary>Provides tls rpt reports time series info functionality.</summary>
public sealed class TlsRptReportsTimeSeriesInfo
{
    /// <summary>Gets or sets the section key value.</summary>
    public string SectionKey { get; set; } = "TLS-RPT Reports";
    /// <summary>Gets or sets the area value.</summary>
    public AnalysisArea Area { get; set; }
    /// <summary>Gets or sets the subject value.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>Gets or sets the period start utc value.</summary>
    public DateTimeOffset? PeriodStartUtc { get; set; }
    /// <summary>Gets or sets the period end utc value.</summary>
    public DateTimeOffset? PeriodEndUtc { get; set; }
    /// <summary>Gets or sets the snapshot count value.</summary>
    public int SnapshotCount { get; set; }

    /// <summary>Gets or sets the total successful sessions value.</summary>
    public int TotalSuccessfulSessions { get; set; }
    /// <summary>Gets or sets the total failed sessions value.</summary>
    public int TotalFailedSessions { get; set; }
    /// <summary>Gets or sets the failure rate percent value.</summary>
    public double FailureRatePercent { get; set; }

    /// <summary>Gets or sets the daily value.</summary>
    public IReadOnlyList<TlsRptDailyStat> Daily { get; set; } = Array.Empty<TlsRptDailyStat>();
    /// <summary>Gets or sets the top failure types value.</summary>
    public IReadOnlyList<NamedCount> TopFailureTypes { get; set; } = Array.Empty<NamedCount>();
    /// <summary>Gets or sets the mx hosts value.</summary>
    public IReadOnlyList<TlsRptMxHostStat> MxHosts { get; set; } = Array.Empty<TlsRptMxHostStat>();

    /// <summary>Gets or sets the assessments value.</summary>
    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    /// <summary>Gets or sets the status value.</summary>
    public string Status { get; set; } = "OK";
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

    /// <summary>Gets or sets the snapshots value.</summary>
    public IReadOnlyList<TlsRptSnapshot> Snapshots { get; set; } = Array.Empty<TlsRptSnapshot>();
}

/// <summary>Provides tls rpt daily stat functionality.</summary>
public sealed class TlsRptDailyStat
{
    /// <summary>Gets or sets the date utc value.</summary>
    public DateTime DateUtc { get; set; }
    /// <summary>Gets or sets the successful sessions value.</summary>
    public int SuccessfulSessions { get; set; }
    /// <summary>Gets or sets the failed sessions value.</summary>
    public int FailedSessions { get; set; }
    /// <summary>Gets or sets the failure rate percent value.</summary>
    public double FailureRatePercent { get; set; }
}

/// <summary>Provides tls rpt mx host stat functionality.</summary>
public sealed class TlsRptMxHostStat
{
    /// <summary>Gets or sets the mx host value.</summary>
    public string MxHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the successful sessions value.</summary>
    public int SuccessfulSessions { get; set; }
    /// <summary>Gets or sets the failed sessions value.</summary>
    public int FailedSessions { get; set; }
    /// <summary>Gets or sets the failure by type value.</summary>
    public Dictionary<string, int> FailureByType { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

