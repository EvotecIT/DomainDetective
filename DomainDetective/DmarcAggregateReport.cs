using System.Collections.Generic;

namespace DomainDetective;

/// <summary>Represents a DMARC aggregate feedback report.</summary>
public sealed class DmarcAggregateReport {
    /// <summary>Published policy of the report.</summary>
    public DmarcPolicyPublished PolicyPublished { get; set; } = new();

    /// <summary>Individual aggregate records contained in the report.</summary>
    public List<DmarcAggregateRecord> Records { get; } = new();

    /// <summary>Schema validation messages encountered during parsing.</summary>
    public List<string> ValidationMessages { get; } = new();

    /// <summary>Total number of parsed records.</summary>
    public int RecordCount => Records.Count;

    /// <summary>Report identifier from metadata (report_id).</summary>
    public string? ReportId { get; set; }

    /// <summary>Start of the reported date range (UTC).</summary>
    public System.DateTimeOffset? RangeBeginUtc { get; set; }

    /// <summary>End of the reported date range (UTC).</summary>
    public System.DateTimeOffset? RangeEndUtc { get; set; }
}
