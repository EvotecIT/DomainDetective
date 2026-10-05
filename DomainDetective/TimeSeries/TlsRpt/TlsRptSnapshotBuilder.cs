using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.TimeSeries.TlsRpt;

internal static class TlsRptSnapshotBuilder {
    internal static TlsRptSnapshot Build(TlsRptReport report, string domain, string source, string? sourceId) {
        if (report == null) throw new ArgumentNullException(nameof(report));
        var allPolicies = report.Policies ?? new List<TlsRptPolicyResult>();
        var domains = allPolicies.Select(p => NormalizeDomain(p.Policy?.PolicyDomain)).Where(d => d.Length > 0).Distinct().ToList();
        string resolvedDomain = NormalizeDomain(domain);
        if (resolvedDomain.Length == 0) {
            if (domains.Count != 1) throw new ArgumentException("A domain is required for reports with no policy-domain or multiple domains.", nameof(domain));
            resolvedDomain = domains[0];
        }
        if (domains.Count > 0 && !domains.Contains(resolvedDomain))
            throw new FormatException($"TLS-RPT report policy-domain mismatch: expected '{resolvedDomain}', found '{string.Join(", ", domains)}'.");

        var selected = domains.Count == 0 ? allPolicies : allPolicies.Where(p => NormalizeDomain(p.Policy?.PolicyDomain) == resolvedDomain).ToList();
        var snapshot = new TlsRptSnapshot {
            Domain = resolvedDomain, ReportId = report.ReportId, RangeBeginUtc = report.RangeBeginUtc,
            RangeEndUtc = report.RangeEndUtc, ReporterOrgName = report.OrganizationName, ContactInfo = report.ContactInfo,
            Source = source, SourceId = sourceId, MxFailureAttributionVerified = true
        };
        if (domains.Count == 0) snapshot.ValidationMessages.Add("Policy domains are missing; the caller supplied the unverified domain scope.");
        else if (selected.Count != allPolicies.Count) snapshot.ValidationMessages.Add("Policies for other or missing domains were excluded from this snapshot.");

        var hosts = new Dictionary<string, TlsRptMxSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in selected) {
            int successful = policy.Summary?.SuccessfulSessionCount ?? 0;
            int failed = policy.Summary?.FailedSessionCount ?? 0;
            if (successful < 0 || failed < 0) throw new FormatException("TLS-RPT session counts must be nonnegative.");
            snapshot.TotalSuccessfulSessions = checked(snapshot.TotalSuccessfulSessions + successful);
            snapshot.TotalFailedSessions = checked(snapshot.TotalFailedSessions + failed);
            int detailsTotal = 0;
            foreach (var detail in policy.FailureDetails) {
                if (detail.FailedSessionCount < 0) throw new FormatException("TLS-RPT failure counts must be nonnegative.");
                int count = detail.FailedSessionCount;
                if (count == 0) continue;
                detailsTotal = checked(detailsTotal + count);
                string kind = string.IsNullOrWhiteSpace(detail.ResultType) ? "unknown" : detail.ResultType;
                string host = string.IsNullOrWhiteSpace(detail.ReceivingMxHostname) ? "(unknown)" : NormalizeDomain(detail.ReceivingMxHostname);
                // A policy wildcard is never delivery evidence, even if repeated in a malformed failure detail.
                if (host.IndexOf('*') >= 0) { host = "(unknown)"; snapshot.ValidationMessages.Add("A receiving MX wildcard was retained as an unattributed failure."); }
                AddFailure(snapshot, hosts, host, kind, count);
            }
            if (detailsTotal < failed) AddFailure(snapshot, hosts, "(unknown)", "unknown", failed - detailsTotal);
            if (detailsTotal > failed) snapshot.ValidationMessages.Add("Failure details exceed the policy total; detail rows retain reported counts and domain totals retain the summary.");
        }
        snapshot.MxHosts = hosts.Values.OrderByDescending(mx => mx.FailedSessions).ThenBy(mx => mx.MxHost, StringComparer.OrdinalIgnoreCase).ToList();
        snapshot.TopFailureTypes = snapshot.FailureTypeCounts.Select(kv => new CountedValue { Key = kv.Key, Count = kv.Value })
            .OrderByDescending(x => x.Count).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Take(10).ToList();
        return snapshot;
    }

    private static void AddFailure(TlsRptSnapshot snapshot, Dictionary<string, TlsRptMxSnapshot> hosts, string host, string kind, int count) {
        if (!hosts.TryGetValue(host, out var row)) hosts[host] = row = new TlsRptMxSnapshot { MxHost = host };
        row.FailedSessions = checked(row.FailedSessions + count);
        row.FailureByType[kind] = checked((row.FailureByType.TryGetValue(kind, out int previous) ? previous : 0) + count);
        snapshot.FailureTypeCounts[kind] = checked((snapshot.FailureTypeCounts.TryGetValue(kind, out int total) ? total : 0) + count);
    }
    private static string NormalizeDomain(string? domain) => (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
}
