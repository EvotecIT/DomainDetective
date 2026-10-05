using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective.TimeSeries.TlsRpt;

/// <summary>Selects one active interpretation of an identified report without deleting historical evidence.</summary>
internal static class TlsRptSnapshotSelection {
    internal static IReadOnlyList<TlsRptSnapshot> SelectCurrent(IEnumerable<TlsRptSnapshot> snapshots) {
        var unidentified = new List<TlsRptSnapshot>();
        var current = new Dictionary<(string Domain, string ReportId, DateTimeOffset Begin, DateTimeOffset End, string Reporter), TlsRptSnapshot>();
        foreach (var snapshot in snapshots) {
            if (snapshot == null) continue;
            // Without an ID and complete period, unrelated reports cannot safely be coalesced.
            if (string.IsNullOrWhiteSpace(snapshot.ReportId) || !snapshot.RangeBeginUtc.HasValue || !snapshot.RangeEndUtc.HasValue) {
                unidentified.Add(snapshot);
                continue;
            }
            var identity = ((snapshot.Domain ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant(), snapshot.ReportId!,
                snapshot.RangeBeginUtc.Value, snapshot.RangeEndUtc.Value, (snapshot.ReporterOrgName ?? string.Empty).Trim().ToLowerInvariant());
            if (!current.TryGetValue(identity, out var existing) || IsNewerInterpretation(snapshot, existing)) current[identity] = snapshot;
        }
        return unidentified.Concat(current.Values).OrderBy(s => s.RangeEndUtc ?? s.IngestedAtUtc).ToList();
    }

    private static bool IsNewerInterpretation(TlsRptSnapshot candidate, TlsRptSnapshot existing) {
        if (candidate.MxFailureAttributionVerified != existing.MxFailureAttributionVerified) return candidate.MxFailureAttributionVerified;
        if (candidate.ReceivingMxInterpretationVersion != existing.ReceivingMxInterpretationVersion) return candidate.ReceivingMxInterpretationVersion > existing.ReceivingMxInterpretationVersion;
        return candidate.IngestedAtUtc > existing.IngestedAtUtc;
    }
}
