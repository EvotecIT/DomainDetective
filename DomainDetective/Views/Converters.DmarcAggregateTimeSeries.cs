using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.TimeSeries.DmarcAggregate;

namespace DomainDetective.Views;

public static partial class Converters
{
    public static DmarcAggregateTimeSeriesInfo Convert(IReadOnlyList<DmarcAggregateSnapshot> snapshots, string? subjectOverride = null)
    {
        var list = (snapshots ?? Array.Empty<DmarcAggregateSnapshot>()).Where(s => s != null).ToList();
        var subject = !string.IsNullOrWhiteSpace(subjectOverride)
            ? subjectOverride!
            : (list.FirstOrDefault()?.Domain ?? string.Empty);

        var assessments = new List<Assessment>();

        int total = list.Sum(s => s.TotalCount);
        int pass = list.Sum(s => s.PassCount);
        int fail = list.Sum(s => s.FailCount);
        double passRate = total > 0 ? (pass * 100.0 / total) : 0.0;

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
                Code = "DMARC.Aggregate.NoData",
                Category = "DMARC",
                Target = subject,
                Message = "No DMARC aggregate reports were found for this domain."
            });
        }
        else if (total <= 0)
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Warning,
                Code = "DMARC.Aggregate.ZeroMessages",
                Category = "DMARC",
                Target = subject,
                Message = "DMARC aggregate reports were ingested, but message count is zero."
            });
        }
        else if (fail > 0)
        {
            var sev = passRate < 80.0 ? AssessmentSeverity.Error : AssessmentSeverity.Warning;
            assessments.Add(new Assessment
            {
                Severity = sev,
                Code = "DMARC.Aggregate.Failures",
                Category = "DMARC",
                Target = subject,
                Message = $"DMARC aggregate reports show {fail} failing messages (pass rate {passRate:0.0}%)."
            });
        }
        else
        {
            assessments.Add(new Assessment
            {
                Severity = AssessmentSeverity.Info,
                Code = "DMARC.Aggregate.AllPass",
                Category = "DMARC",
                Target = subject,
                Message = "DMARC aggregate reports show 100% authentication pass rate for observed mail."
            });
        }

        Summarize(assessments, out var warnCount, out var errCount, out var status);
        var recs = RecommendationEngine.FromProblems(assessments);
        var positives = RecommendationEngine.FromPositives(assessments);

        return new DmarcAggregateTimeSeriesInfo
        {
            SectionKey = "DMARC Aggregate",
            Area = AreaForKind(HealthCheckType.DMARC),
            Subject = subject,
            PeriodStartUtc = start,
            PeriodEndUtc = end,
            SnapshotCount = list.Count,
            TotalCount = total,
            PassCount = pass,
            FailCount = fail,
            PassRatePercent = passRate,
            Daily = BuildDaily(list),
            DispositionCounts = AggregateDispositions(list),
            TopFailingSourceIps = AggregateTop(list.SelectMany(s => s.TopFailingSourceIps)),
            TopFailingHeaderFrom = AggregateTop(list.SelectMany(s => s.TopFailingHeaderFrom)),
            TopFailingDkimDomains = AggregateTop(list.SelectMany(s => s.TopFailingDkimDomains)),
            TopFailingSpfDomains = AggregateTop(list.SelectMany(s => s.TopFailingSpfDomains)),
            Snapshots = list,
            Assessments = assessments,
            Status = status,
            WarningCount = warnCount,
            ErrorCount = errCount,
            Summary = total > 0
                ? $"reports {list.Count}; pass {pass}/{total} ({passRate:0.0}%); fail {fail}"
                : $"reports {list.Count}; no message count",
            Recommendations = recs,
            Positives = positives,
            References = new[] { "https://www.rfc-editor.org/rfc/rfc7489" }
        };
    }

    private static List<DmarcAggregateDailyStat> BuildDaily(List<DmarcAggregateSnapshot> snaps)
    {
        var list = new List<DmarcAggregateDailyStat>();
        if (snaps == null || snaps.Count == 0) return list;

        var grouped = snaps
            .GroupBy(s => (s.RangeEndUtc ?? s.IngestedAtUtc).UtcDateTime.Date)
            .OrderBy(g => g.Key);

        foreach (var g in grouped)
        {
            int total = g.Sum(x => x.TotalCount);
            int pass = g.Sum(x => x.PassCount);
            int fail = g.Sum(x => x.FailCount);
            double passRate = total > 0 ? (pass * 100.0 / total) : 0.0;

            list.Add(new DmarcAggregateDailyStat
            {
                DateUtc = g.Key,
                TotalCount = total,
                PassCount = pass,
                FailCount = fail,
                PassRatePercent = passRate
            });
        }

        return list;
    }

    private static Dictionary<string, int> AggregateDispositions(List<DmarcAggregateSnapshot> snaps)
    {
        var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in snaps ?? new List<DmarcAggregateSnapshot>())
        {
            foreach (var kv in s.DispositionCounts ?? new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(kv.Key)) continue;
                dict[kv.Key] = (dict.TryGetValue(kv.Key, out var prev) ? prev : 0) + kv.Value;
            }
        }
        return dict;
    }

    private static List<NamedCount> AggregateTop(IEnumerable<DomainDetective.TimeSeries.DmarcAggregate.CountedValue> values)
    {
        var dict = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in values ?? Array.Empty<DomainDetective.TimeSeries.DmarcAggregate.CountedValue>())
        {
            if (v == null || string.IsNullOrWhiteSpace(v.Key) || v.Count <= 0) continue;
            dict[v.Key] = (dict.TryGetValue(v.Key, out var prev) ? prev : 0) + v.Count;
        }

        return dict
            .Select(kv => new NamedCount { Key = kv.Key, Count = kv.Value })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();
    }
}

public sealed class DmarcAggregateTimeSeriesInfo
{
    public string SectionKey { get; set; } = "DMARC Aggregate";
    public AnalysisArea Area { get; set; }
    public string Subject { get; set; } = string.Empty;

    public DateTimeOffset? PeriodStartUtc { get; set; }
    public DateTimeOffset? PeriodEndUtc { get; set; }
    public int SnapshotCount { get; set; }

    public int TotalCount { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public double PassRatePercent { get; set; }

    public IReadOnlyList<DmarcAggregateDailyStat> Daily { get; set; } = Array.Empty<DmarcAggregateDailyStat>();
    public Dictionary<string, int> DispositionCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<NamedCount> TopFailingSourceIps { get; set; } = Array.Empty<NamedCount>();
    public IReadOnlyList<NamedCount> TopFailingHeaderFrom { get; set; } = Array.Empty<NamedCount>();
    public IReadOnlyList<NamedCount> TopFailingDkimDomains { get; set; } = Array.Empty<NamedCount>();
    public IReadOnlyList<NamedCount> TopFailingSpfDomains { get; set; } = Array.Empty<NamedCount>();

    public IReadOnlyList<Assessment> Assessments { get; set; } = Array.Empty<Assessment>();
    public string Status { get; set; } = "OK";
    public int WarningCount { get; set; }
    public int ErrorCount { get; set; }
    public string Summary { get; set; } = string.Empty;
    public IReadOnlyList<RecommendationAdvice> Recommendations { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<RecommendationAdvice> Positives { get; set; } = Array.Empty<RecommendationAdvice>();
    public IReadOnlyList<string> References { get; set; } = Array.Empty<string>();

    public IReadOnlyList<DmarcAggregateSnapshot> Snapshots { get; set; } = Array.Empty<DmarcAggregateSnapshot>();
}

public sealed class DmarcAggregateDailyStat
{
    public DateTime DateUtc { get; set; }
    public int TotalCount { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }
    public double PassRatePercent { get; set; }
}

public sealed class NamedCount
{
    public string Key { get; set; } = string.Empty;
    public int Count { get; set; }
}

