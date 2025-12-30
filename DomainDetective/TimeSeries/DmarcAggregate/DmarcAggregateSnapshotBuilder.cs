using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.TimeSeries.DmarcAggregate;

internal static class DmarcAggregateSnapshotBuilder
{
    internal static DmarcAggregateSnapshot Build(DmarcAggregateReport report, string source, string? sourceId)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var domain = DetermineDomain(report);
        var snapshot = new DmarcAggregateSnapshot
        {
            Domain = domain,
            ReportId = report.ReportId,
            RangeBeginUtc = report.RangeBeginUtc,
            RangeEndUtc = report.RangeEndUtc,
            ReporterOrgName = report.ReporterOrgName,
            ReporterEmail = report.ReporterEmail,
            Source = string.IsNullOrWhiteSpace(source) ? "File" : source.Trim(),
            SourceId = sourceId
        };

        snapshot.ValidationMessages.AddRange(report.ValidationMessages ?? new List<string>());

        var dispositions = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        int total = 0;
        int pass = 0;
        int fail = 0;

        var ipFailures = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var headerFailures = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var dkimDomFailures = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var spfDomFailures = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        foreach (var r in report.Records ?? new List<DmarcAggregateRecord>())
        {
            if (r == null) continue;
            var count = r.Count < 0 ? 0 : r.Count;
            total += count;

            var disp = (r.Disposition ?? string.Empty).Trim();
            if (!string.IsNullOrWhiteSpace(disp))
            {
                dispositions[disp] = (dispositions.TryGetValue(disp, out var c) ? c : 0) + count;
            }

            if (r.IsPass)
            {
                pass += count;
            }
            else
            {
                fail += count;
                if (!string.IsNullOrWhiteSpace(r.SourceIp))
                {
                    ipFailures[r.SourceIp] = (ipFailures.TryGetValue(r.SourceIp, out var c) ? c : 0) + count;
                }
                if (!string.IsNullOrWhiteSpace(r.HeaderFrom))
                {
                    headerFailures[r.HeaderFrom] = (headerFailures.TryGetValue(r.HeaderFrom, out var c) ? c : 0) + count;
                }
                if (!string.IsNullOrWhiteSpace(r.DkimDomain))
                {
                    var k = r.DkimDomain!.Trim();
                    dkimDomFailures[k] = (dkimDomFailures.TryGetValue(k, out var c) ? c : 0) + count;
                }
                if (!string.IsNullOrWhiteSpace(r.SpfDomain))
                {
                    var k = r.SpfDomain!.Trim();
                    spfDomFailures[k] = (spfDomFailures.TryGetValue(k, out var c) ? c : 0) + count;
                }
            }
        }

        snapshot.TotalCount = total;
        snapshot.PassCount = pass;
        snapshot.FailCount = fail;
        snapshot.DispositionCounts = dispositions;
        snapshot.TopFailingSourceIps = Top(ipFailures, 10);
        snapshot.TopFailingHeaderFrom = Top(headerFailures, 10);
        snapshot.TopFailingDkimDomains = Top(dkimDomFailures, 10);
        snapshot.TopFailingSpfDomains = Top(spfDomFailures, 10);

        return snapshot;
    }

    private static string DetermineDomain(DmarcAggregateReport report)
    {
        var d = report.PolicyPublished?.Domain;
        if (!string.IsNullOrWhiteSpace(d))
        {
            return d!.Trim();
        }

        var tally = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in report.Records ?? new List<DmarcAggregateRecord>())
        {
            if (r == null) continue;
            if (string.IsNullOrWhiteSpace(r.HeaderFrom)) continue;
            var k = r.HeaderFrom.Trim();
            tally[k] = (tally.TryGetValue(k, out var c) ? c : 0) + Math.Max(0, r.Count);
        }

        if (tally.Count == 0)
        {
            return "unknown";
        }

        return tally.OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .First().Key;
    }

    private static List<CountedValue> Top(Dictionary<string, int> map, int take)
    {
        return map.OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Max(1, take))
            .Select(kv => new CountedValue { Key = kv.Key, Count = kv.Value })
            .ToList();
    }
}

