using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.DmarcAggregate;

/// <summary>Provides dmarc aggregate snapshot functionality.</summary>
public sealed class DmarcAggregateSnapshot
{
    /// <summary>Gets or sets the domain value.</summary>
    public string Domain { get; set; } = string.Empty;
    /// <summary>Gets or sets the report id value.</summary>
    public string? ReportId { get; set; }
    /// <summary>Gets or sets the range begin utc value.</summary>
    public DateTimeOffset? RangeBeginUtc { get; set; }
    /// <summary>Gets or sets the range end utc value.</summary>
    public DateTimeOffset? RangeEndUtc { get; set; }
    /// <summary>Gets or sets the reporter org name value.</summary>
    public string? ReporterOrgName { get; set; }
    /// <summary>Gets or sets the reporter email value.</summary>
    public string? ReporterEmail { get; set; }

    /// <summary>Gets or sets the total count value.</summary>
    public int TotalCount { get; set; }
    /// <summary>Gets or sets the pass count value.</summary>
    public int PassCount { get; set; }
    /// <summary>Gets or sets the fail count value.</summary>
    public int FailCount { get; set; }

    /// <summary>Gets or sets the disposition counts value.</summary>
    public Dictionary<string, int> DispositionCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets or sets the top failing source ips value.</summary>
    public List<CountedValue> TopFailingSourceIps { get; set; } = new();
    /// <summary>Gets or sets the top failing header from value.</summary>
    public List<CountedValue> TopFailingHeaderFrom { get; set; } = new();
    /// <summary>Gets or sets the top failing dkim domains value.</summary>
    public List<CountedValue> TopFailingDkimDomains { get; set; } = new();
    /// <summary>Gets or sets the top failing spf domains value.</summary>
    public List<CountedValue> TopFailingSpfDomains { get; set; } = new();

    /// <summary>Gets or sets the validation messages value.</summary>
    public List<string> ValidationMessages { get; set; } = new();

    /// <summary>Gets or sets the ingested at utc value.</summary>
    public DateTimeOffset IngestedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Gets or sets the source value.</summary>
    public string Source { get; set; } = "File"; // File | IMAP
    /// <summary>Gets or sets the source id value.</summary>
    public string? SourceId { get; set; } // file path or message-id
}

/// <summary>Provides counted value functionality.</summary>
public sealed class CountedValue
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the count value.</summary>
    public int Count { get; set; }
}

