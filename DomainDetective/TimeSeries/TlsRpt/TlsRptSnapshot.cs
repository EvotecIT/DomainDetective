using System;
using System.Collections.Generic;

namespace DomainDetective.TimeSeries.TlsRpt;

/// <summary>Provides tls rpt snapshot functionality.</summary>
public sealed class TlsRptSnapshot
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
    /// <summary>Gets or sets the contact info value.</summary>
    public string? ContactInfo { get; set; }

    /// <summary>Gets or sets the total successful sessions value.</summary>
    public int TotalSuccessfulSessions { get; set; }
    /// <summary>Gets or sets the total failed sessions value.</summary>
    public int TotalFailedSessions { get; set; }

    /// <summary>Gets or sets the failure type counts value.</summary>
    public Dictionary<string, int> FailureTypeCounts { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Gets or sets the mx hosts value.</summary>
    public List<TlsRptMxSnapshot> MxHosts { get; set; } = new();
    /// <summary>Gets or sets the top failure types value.</summary>
    public List<CountedValue> TopFailureTypes { get; set; } = new();

    /// <summary>Gets or sets the validation messages value.</summary>
    public List<string> ValidationMessages { get; set; } = new();

    /// <summary>Gets or sets the ingested at utc value.</summary>
    public DateTimeOffset IngestedAtUtc { get; set; } = DateTimeOffset.UtcNow;
    /// <summary>Gets or sets the source value.</summary>
    public string Source { get; set; } = "File"; // File | IMAP
    /// <summary>Gets or sets the source id value.</summary>
    public string? SourceId { get; set; } // file path or attachment name
}

/// <summary>Provides tls rpt mx snapshot functionality.</summary>
public sealed class TlsRptMxSnapshot
{
    /// <summary>Gets or sets the mx host value.</summary>
    public string MxHost { get; set; } = string.Empty;
    /// <summary>Gets or sets the successful sessions value.</summary>
    public int SuccessfulSessions { get; set; }
    /// <summary>Gets or sets the failed sessions value.</summary>
    public int FailedSessions { get; set; }
    /// <summary>Gets or sets the failure by type value.</summary>
    public Dictionary<string, int> FailureByType { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Provides counted value functionality.</summary>
public sealed class CountedValue
{
    /// <summary>Gets or sets the key value.</summary>
    public string Key { get; set; } = string.Empty;
    /// <summary>Gets or sets the count value.</summary>
    public int Count { get; set; }
}

