using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.DmarcAggregate;

public sealed class DmarcAggregateSnapshot
{
    public string Domain { get; set; } = string.Empty;
    public string? ReportId { get; set; }
    public DateTimeOffset? RangeBeginUtc { get; set; }
    public DateTimeOffset? RangeEndUtc { get; set; }
    public string? ReporterOrgName { get; set; }
    public string? ReporterEmail { get; set; }

    public int TotalCount { get; set; }
    public int PassCount { get; set; }
    public int FailCount { get; set; }

    public Dictionary<string, int> DispositionCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<CountedValue> TopFailingSourceIps { get; set; } = new();
    public List<CountedValue> TopFailingHeaderFrom { get; set; } = new();
    public List<CountedValue> TopFailingDkimDomains { get; set; } = new();
    public List<CountedValue> TopFailingSpfDomains { get; set; } = new();

    public List<string> ValidationMessages { get; set; } = new();

    public DateTimeOffset IngestedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    public string Source { get; set; } = "File"; // File | IMAP
    public string? SourceId { get; set; } // file path or message-id
}

public sealed class CountedValue
{
    public string Key { get; set; } = string.Empty;
    public int Count { get; set; }
}

