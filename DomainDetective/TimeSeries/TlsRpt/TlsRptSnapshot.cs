using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.TlsRpt;

public sealed class TlsRptSnapshot
{
    public string Domain { get; set; } = string.Empty;
    public string? ReportId { get; set; }
    public DateTimeOffset? RangeBeginUtc { get; set; }
    public DateTimeOffset? RangeEndUtc { get; set; }
    public string? ReporterOrgName { get; set; }
    public string? ContactInfo { get; set; }

    public int TotalSuccessfulSessions { get; set; }
    public int TotalFailedSessions { get; set; }

    public Dictionary<string, int> FailureTypeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<TlsRptMxSnapshot> MxHosts { get; set; } = new();
    public List<CountedValue> TopFailureTypes { get; set; } = new();

    public List<string> ValidationMessages { get; set; } = new();

    public DateTimeOffset IngestedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "File"; // File | IMAP
    public string? SourceId { get; set; } // file path or attachment name
}

public sealed class TlsRptMxSnapshot
{
    public string MxHost { get; set; } = string.Empty;
    public int SuccessfulSessions { get; set; }
    public int FailedSessions { get; set; }
    public Dictionary<string, int> FailureByType { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class CountedValue
{
    public string Key { get; set; } = string.Empty;
    public int Count { get; set; }
}

