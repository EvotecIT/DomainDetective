using System;
using System.Collections.Generic;

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
    /// <remarks>
    /// DMARC pass/fail is determined by the aligned SPF/DKIM results (policy_evaluated/spf|dkim),
    /// not by the disposition (p=none can still have failures with disposition=none).
    /// </remarks>
    public bool IsPass => string.Equals(Dkim, "pass", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Spf, "pass", StringComparison.OrdinalIgnoreCase);

    /// <summary>SPF authenticated domain (auth_results/spf/domain).</summary>
    public string? SpfDomain { get; set; }

    /// <summary>SPF result (auth_results/spf/result).</summary>
    public string? SpfResult { get; set; }

    /// <summary>DKIM signing domain (auth_results/dkim/domain).</summary>
    public string? DkimDomain { get; set; }

    /// <summary>DKIM selector (auth_results/dkim/selector).</summary>
    public string? DkimSelector { get; set; }

    /// <summary>DKIM result (auth_results/dkim/result).</summary>
    public string? DkimResult { get; set; }

    /// <summary>Policy evaluation reasons (policy_evaluated/reason/type and comments).</summary>
    public List<string> Reasons { get; set; } = new List<string>();

    /// <summary>Enriched: Origin ASN for SourceIp when available.</summary>
    public int? Asn { get; set; }

    /// <summary>Enriched: Country derived from SourceIp.</summary>
    public string? Country { get; set; }
}

