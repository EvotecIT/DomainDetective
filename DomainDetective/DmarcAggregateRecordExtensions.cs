using System.Collections.Generic;
using System.Linq;

namespace DomainDetective;

/// <summary>Summary of DMARC failures grouped by source IP.</summary>
public sealed class SourceIpSummary {
    /// <summary>IP address that generated the failures.</summary>
    public string SourceIp { get; set; } = string.Empty;

    /// <summary>Total failures from the IP address.</summary>
    public int Count { get; set; }
}

/// <summary>Summary of DMARC failures grouped by From header.</summary>
public sealed class HeaderFromSummary {
    /// <summary>Domain found in the message's From header.</summary>
    public string HeaderFrom { get; set; } = string.Empty;

    /// <summary>Total failures for the domain.</summary>
    public int Count { get; set; }
}

/// <summary>Convenience methods for working with DMARC aggregate records.</summary>
public static class DmarcAggregateRecordExtensions {
    /// <summary>Returns only the records that failed DMARC evaluation.</summary>
    /// <param name="records">Collection of parsed DMARC records.</param>
    public static IEnumerable<DmarcAggregateRecord> GetFailureRecords(this IEnumerable<DmarcAggregateRecord> records) {
        return records.Where(r => !r.IsPass);
    }

    /// <summary>Summarizes failed records by source IP address.</summary>
    /// <param name="records">Collection of parsed DMARC records.</param>
    public static IEnumerable<SourceIpSummary> SummarizeFailuresByIp(this IEnumerable<DmarcAggregateRecord> records) {
        var failures = records.GetFailureRecords().ToList();
        return failures.GroupBy(r => r.SourceIp, r => r.Count, (s, c) => new SourceIpSummary { SourceIp = s, Count = c.Sum() });
    }

    /// <summary>Summarizes failed records by From header domain.</summary>
    /// <param name="records">Collection of parsed DMARC records.</param>
    public static IEnumerable<HeaderFromSummary> SummarizeFailuresByHeaderFrom(this IEnumerable<DmarcAggregateRecord> records) {
        var failures = records.GetFailureRecords().ToList();
        return failures.GroupBy(r => r.HeaderFrom, r => r.Count, (h, c) => new HeaderFromSummary { HeaderFrom = h, Count = c.Sum() });
    }
}

