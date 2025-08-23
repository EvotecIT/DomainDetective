using System;

namespace DomainDetective;

/// <summary>Represents a single row from a DMARC aggregate report.</summary>
public sealed class DmarcAggregateRecord {
    /// <summary>IP address that sent the message.</summary>
    public string SourceIp { get; set; } = string.Empty;

    /// <summary>Domain found in the message's From header.</summary>
    public string HeaderFrom { get; set; } = string.Empty;

    /// <summary>Number of messages for this record.</summary>
    public int Count { get; set; }

    /// <summary>DKIM evaluation result.</summary>
    public string Dkim { get; set; } = string.Empty;

    /// <summary>SPF evaluation result.</summary>
    public string Spf { get; set; } = string.Empty;

    /// <summary>Policy disposition applied.</summary>
    public string Disposition { get; set; } = string.Empty;

    /// <summary>Indicates whether the record passed DMARC evaluation.</summary>
    public bool IsPass => (string.Equals(Dkim, "pass", StringComparison.OrdinalIgnoreCase)
            || string.Equals(Spf, "pass", StringComparison.OrdinalIgnoreCase))
        && !string.Equals(Disposition, "reject", StringComparison.OrdinalIgnoreCase)
        && !string.Equals(Disposition, "quarantine", StringComparison.OrdinalIgnoreCase);
}

