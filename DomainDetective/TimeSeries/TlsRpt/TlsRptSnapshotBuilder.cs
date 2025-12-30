using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.TimeSeries.TlsRpt;

internal static class TlsRptSnapshotBuilder
{
    internal static TlsRptSnapshot Build(TlsRptReport report, string domain, string source, string? sourceId)
    {
        if (report == null) throw new ArgumentNullException(nameof(report));

        var resolvedDomain = DetermineDomain(report, domain);
        if (string.IsNullOrWhiteSpace(resolvedDomain))
        {
            throw new ArgumentException("Domain is required (unable to infer from report).", nameof(domain));
        }

        var snapshot = new TlsRptSnapshot
        {
            Domain = resolvedDomain,
            ReportId = report.ReportId,
            RangeBeginUtc = report.RangeBeginUtc,
            RangeEndUtc = report.RangeEndUtc,
            ReporterOrgName = string.IsNullOrWhiteSpace(report.OrganizationName) ? null : report.OrganizationName,
            ContactInfo = string.IsNullOrWhiteSpace(report.ContactInfo) ? null : report.ContactInfo,
            Source = source,
            SourceId = sourceId
        };

        var mxMap = new Dictionary<string, TlsRptMxSnapshot>(StringComparer.OrdinalIgnoreCase);

        foreach (var p in report.Policies ?? new List<TlsRptPolicyResult>())
        {
            var mxHost = p.Policy?.MxHost ?? string.Empty;
            if (string.IsNullOrWhiteSpace(mxHost))
            {
                mxHost = "(unknown)";
            }

            if (!mxMap.TryGetValue(mxHost, out var mx))
            {
                mx = new TlsRptMxSnapshot { MxHost = mxHost };
                mxMap[mxHost] = mx;
            }

            int ok = p.Summary?.SuccessfulSessionCount ?? 0;
            int fail = p.Summary?.FailedSessionCount ?? 0;

            snapshot.TotalSuccessfulSessions += ok;
            snapshot.TotalFailedSessions += fail;
            mx.SuccessfulSessions += ok;
            mx.FailedSessions += fail;

            int detailsTotal = 0;
            if (p.FailureDetails != null && p.FailureDetails.Count > 0)
            {
                foreach (var fd in p.FailureDetails)
                {
                    var kind = string.IsNullOrWhiteSpace(fd.ResultType) ? "unknown" : fd.ResultType;
                    var cnt = Math.Max(0, fd.FailedSessionCount);
                    if (cnt == 0) continue;

                    detailsTotal += cnt;
                    snapshot.FailureTypeCounts[kind] = (snapshot.FailureTypeCounts.TryGetValue(kind, out var prev) ? prev : 0) + cnt;
                    mx.FailureByType[kind] = (mx.FailureByType.TryGetValue(kind, out var prevMx) ? prevMx : 0) + cnt;
                }
            }

            var delta = fail - detailsTotal;
            if (delta > 0)
            {
                snapshot.FailureTypeCounts["unknown"] = (snapshot.FailureTypeCounts.TryGetValue("unknown", out var prev) ? prev : 0) + delta;
                mx.FailureByType["unknown"] = (mx.FailureByType.TryGetValue("unknown", out var prevMx) ? prevMx : 0) + delta;
            }
        }

        snapshot.MxHosts = mxMap.Values
            .OrderByDescending(x => x.FailedSessions)
            .ThenBy(x => x.MxHost, StringComparer.OrdinalIgnoreCase)
            .ToList();

        snapshot.TopFailureTypes = snapshot.FailureTypeCounts
            .Select(kv => new CountedValue { Key = kv.Key, Count = kv.Value })
            .OrderByDescending(x => x.Count)
            .ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase)
            .Take(10)
            .ToList();

        return snapshot;
    }

    private static string DetermineDomain(TlsRptReport report, string domain)
    {
        if (!string.IsNullOrWhiteSpace(domain))
        {
            return domain.Trim();
        }

        foreach (var p in report.Policies ?? new List<TlsRptPolicyResult>())
        {
            var pd = p.Policy?.PolicyDomain;
            if (!string.IsNullOrWhiteSpace(pd))
            {
                return pd!.Trim();
            }
        }

        return string.Empty;
    }
}
