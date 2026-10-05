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
        bool callerScope = resolvedDomain.Length > 0;
        bool daneOnly = allPolicies.Count > 0 && allPolicies.All(IsDane);
        if (!callerScope) {
            if (daneOnly) throw new ArgumentException("A recipient domain is required for DANE reports; the TLSA base domain does not identify the recipient.", nameof(domain));
            if (domains.Count != 1) throw new ArgumentException("A domain is required for reports with no policy-domain or multiple domains.", nameof(domain));
            resolvedDomain = domains[0];
        }
        var recipientPolicies = allPolicies.Where(p => NormalizeDomain(p.Policy?.PolicyDomain) == resolvedDomain).ToList();
        if (domains.Count > 0 && recipientPolicies.Count == 0 && !(callerScope && daneOnly))
            throw new FormatException($"TLS-RPT report policy-domain mismatch: expected '{resolvedDomain}', found '{string.Join(", ", domains)}'.");
        // DANE policy-domain is the TLSA base domain, not the envelope recipient.
        // Mixed reports bind it to receiving MX patterns from the selected recipient policy.
        // DANE-only reports need the caller's report-level recipient context.
        var selected = domains.Count == 0 ? allPolicies : allPolicies.Where(p => recipientPolicies.Contains(p)
            || IsDane(p) && (callerScope && daneOnly || recipientPolicies.Any(r => r.Policy.MxHostPatterns.Any(pattern => MatchesMx(pattern, p.Policy.PolicyDomain))))).ToList();
        var snapshot = new TlsRptSnapshot {
            Domain = resolvedDomain, ReportId = report.ReportId, RangeBeginUtc = report.RangeBeginUtc,
            RangeEndUtc = report.RangeEndUtc, ReporterOrgName = report.OrganizationName, ContactInfo = report.ContactInfo,
            Source = source, SourceId = sourceId, MxFailureAttributionVerified = true, ReceivingMxInterpretationVersion = 2
        };
        if (domains.Count == 0 || callerScope && daneOnly && recipientPolicies.Count == 0)
            snapshot.ValidationMessages.Add("The caller supplied the report recipient scope; policy domains alone do not verify it.");
        if (selected.Count != allPolicies.Count) snapshot.ValidationMessages.Add("Policies for other or missing domains were excluded from this snapshot.");
        if (selected.Count > 1) snapshot.ValidationMessages.Add("Session totals are per applied policy; multiple policies may cover the same SMTP sessions.");

        var hosts = new Dictionary<string, TlsRptMxSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var policy in selected) AddPolicy(snapshot, hosts, policy);
        snapshot.MxHosts = hosts.Values.OrderByDescending(mx => mx.FailedSessions).ThenBy(mx => mx.MxHost, StringComparer.OrdinalIgnoreCase).ToList();
        snapshot.TopFailureTypes = snapshot.FailureTypeCounts.Select(kv => new CountedValue { Key = kv.Key, Count = kv.Value })
            .OrderByDescending(x => x.Count).ThenBy(x => x.Key, StringComparer.OrdinalIgnoreCase).Take(10).ToList();
        return snapshot;
    }

    private static void AddPolicy(TlsRptSnapshot snapshot, Dictionary<string, TlsRptMxSnapshot> hosts, TlsRptPolicyResult policy) {
        int successful = policy.Summary?.SuccessfulSessionCount ?? 0;
        int failed = policy.Summary?.FailedSessionCount ?? 0;
        if (successful < 0 || failed < 0) throw new FormatException("TLS-RPT session counts must be nonnegative.");
        snapshot.TotalSuccessfulSessions = checked(snapshot.TotalSuccessfulSessions + successful);
        snapshot.TotalFailedSessions = checked(snapshot.TotalFailedSessions + failed);
        var policyHosts = new Dictionary<string, TlsRptMxSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var detail in policy.FailureDetails) {
            int count = detail.FailedSessionCount;
            if (count < 0) throw new FormatException("TLS-RPT failure counts must be nonnegative.");
            if (count == 0) continue;
            string kind = string.IsNullOrWhiteSpace(detail.ResultType) ? "unknown" : detail.ResultType.Trim();
            string host = string.IsNullOrWhiteSpace(detail.ReceivingMxHostname) ? "(unknown)" : NormalizeDomain(detail.ReceivingMxHostname);
            if (host.IndexOf('*') >= 0) { host = "(unknown)"; snapshot.ValidationMessages.Add("A receiving MX wildcard was retained as an unattributed failure."); }
            if (!policyHosts.TryGetValue(host, out var row)) policyHosts[host] = row = new TlsRptMxSnapshot { MxHost = host };
            row.FailureByType[kind] = checked((row.FailureByType.TryGetValue(kind, out int previous) ? previous : 0) + count);
            snapshot.FailureTypeCounts[kind] = checked((snapshot.FailureTypeCounts.TryGetValue(kind, out int total) ? total : 0) + count);
        }
        // Result types overlap. A host's union lies between its largest type count and
        // the sum of its types, bounded by the policy summary and other hosts' minima.
        int minimum = policyHosts.Values.Aggregate(0, (sum, row) => checked(sum + row.FailureByType.Values.Max()));
        foreach (var row in policyHosts.Values) {
            int lower = row.FailureByType.Values.Max();
            int upper = Math.Min(row.FailureByType.Values.Aggregate(0, (sum, count) => checked(sum + count)), failed - (minimum - lower));
            row.FailedSessionsKnown = lower == upper && minimum <= failed;
            row.FailedSessions = row.FailedSessionsKnown ? lower : 0;
        }
        if (policyHosts.Values.All(row => row.FailedSessionsKnown)) {
            int attributed = policyHosts.Values.Sum(row => row.FailedSessions);
            int residual = failed - attributed;
            if (residual > 0) {
                if (!policyHosts.TryGetValue("(unknown)", out var unknown)) policyHosts["(unknown)"] = unknown = new TlsRptMxSnapshot { MxHost = "(unknown)", FailedSessionsKnown = true };
                unknown.FailedSessions = checked(unknown.FailedSessions + residual);
                unknown.FailureByType["unknown"] = checked((unknown.FailureByType.TryGetValue("unknown", out int priorUnknown) ? priorUnknown : 0) + residual);
                snapshot.FailureTypeCounts["unknown"] = checked((snapshot.FailureTypeCounts.TryGetValue("unknown", out int old) ? old : 0) + residual);
            }
        } else {
            snapshot.ValidationMessages.Add("Non-exclusive or inconsistent failure details cannot determine distinct sessions per receiving host; per-type counts and policy summaries remain reported.");
        }
        foreach (var row in policyHosts.Values) {
            if (!hosts.TryGetValue(row.MxHost, out var aggregate)) {
                hosts[row.MxHost] = aggregate = new TlsRptMxSnapshot { MxHost = row.MxHost,
                    FailedSessionsKnown = row.FailedSessionsKnown, FailedSessions = row.FailedSessions };
            } else {
                // Applied policies can describe the same sessions. Their receiving-host
                // observations do not establish a disjoint union across policies.
                aggregate.FailedSessionsKnown = false;
                aggregate.FailedSessions = 0;
            }
            foreach (var pair in row.FailureByType) aggregate.FailureByType[pair.Key] = checked((aggregate.FailureByType.TryGetValue(pair.Key, out int old) ? old : 0) + pair.Value);
        }
    }

    private static bool IsDane(TlsRptPolicyResult policy) => string.Equals(policy.Policy?.PolicyType, "tlsa", StringComparison.OrdinalIgnoreCase);
    private static bool MatchesMx(string? pattern, string? host) {
        pattern = NormalizeDomain(pattern); host = NormalizeDomain(host);
        if (!pattern.StartsWith("*.", StringComparison.Ordinal)) return host == pattern;
        string suffix = pattern.Substring(1);
        if (!host.EndsWith(suffix, StringComparison.Ordinal)) return false;
        string label = host.Substring(0, host.Length - suffix.Length);
        return label.Length > 0 && label.IndexOf('.') < 0;
    }
    private static string NormalizeDomain(string? domain) => (domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();
}
