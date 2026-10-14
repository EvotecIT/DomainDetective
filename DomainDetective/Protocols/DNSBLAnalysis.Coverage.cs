using System;
using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

public partial class DNSBLAnalysis {
    internal static string GetRecordTargetKey(DNSBLRecord record) =>
        !string.IsNullOrWhiteSpace(record.IpAddress) ? record.IpAddress! :
        !string.IsNullOrWhiteSpace(record.SourceHost) ? record.SourceHost! : record.Query ?? string.Empty;

    /// <summary>Projects retained coverage while preserving Results as the latest result per target.</summary>
    internal IReadOnlyDictionary<string, DNSQueryResult> GetCoverageResults() {
        var coverage = new Dictionary<string, DNSQueryResult>(StringComparer.OrdinalIgnoreCase);
        foreach (var result in Results) { coverage[result.Key] = result.Value; }
        foreach (var group in AllResults.Where(record => !string.IsNullOrWhiteSpace(GetRecordTargetKey(record)))
            .GroupBy(GetRecordTargetKey, StringComparer.OrdinalIgnoreCase)) {
            coverage[group.Key] = new DNSQueryResult { Host = group.Key, DNSBLRecords = group.ToArray() };
        }
        return coverage;
    }
}
