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

    /// <summary>Reporting organization name (report_metadata/org_name).</summary>
    public string? ReporterOrgName { get; set; }

    /// <summary>Reporter contact email (report_metadata/email).</summary>
    public string? ReporterEmail { get; set; }

    /// <summary>XML namespace identifying the report format.</summary>
    public string XmlNamespace { get; set; } = string.Empty;
    /// <summary>Report format version declared by the reporter.</summary>
    public string? Version { get; set; }
    /// <summary>Software identified in report_metadata/generator.</summary>
    public string? Generator { get; set; }
    /// <summary>Additional contact information supplied by the reporter.</summary>
    public string? ExtraContactInfo { get; set; }
    /// <summary>Errors reported by the generator, separate from local schema validation messages.</summary>
    public List<string> ReportedErrors { get; } = new();
    /// <summary>Uninterpreted top-level extension elements, serialized with their XML namespaces.</summary>
    public List<string> Extensions { get; } = new();
}
