using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Storage-free aggregate view of domain evidence suitable for persistence by higher-level products.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioSnapshot {
    /// <summary>Snapshot contract version for persistence and migration.</summary>
    public int SchemaVersion { get; set; } = 1;

    /// <summary>Domain or host that was assessed.</summary>
    public string Subject { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the snapshot was synthesized.</summary>
    public DateTimeOffset CapturedAtUtc { get; set; }

    /// <summary>Version of the DomainDetective assembly that synthesized the snapshot.</summary>
    public string EvaluatorVersion { get; set; } = string.Empty;

    /// <summary>Evidence sections keyed by health check or product-neutral domain area.</summary>
    public List<DomainPortfolioSection> Sections { get; set; } = new();

    /// <summary>Typed high-value summaries for storage and dashboard projections.</summary>
    public DomainPortfolioSummaries Summaries { get; set; } = new();

    /// <summary>Flattened assessments from all snapshot sections.</summary>
    public List<Assessment> Assessments { get; set; } = new();
}

/// <summary>
/// Compact typed summary projections for common portfolio workflows.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioSummaries {
    /// <summary>Registration and registrar lifecycle summary.</summary>
    public DomainRegistrationPortfolioSummary Registration { get; set; } = new();

    /// <summary>DNS infrastructure summary.</summary>
    public DomainDnsPortfolioSummary Dns { get; set; } = new();

    /// <summary>Certificate and TLS summary.</summary>
    public DomainCertificatePortfolioSummary Certificate { get; set; } = new();

    /// <summary>Mail authentication and transport summary.</summary>
    public DomainMailPortfolioSummary Mail { get; set; } = new();

    /// <summary>Website and HTTP posture summary.</summary>
    public DomainWebsitePortfolioSummary Website { get; set; } = new();
}

/// <summary>
/// Registration lifecycle fields that are useful to portfolio storage.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainRegistrationPortfolioSummary {
    /// <summary>Registrar name when available.</summary>
    public string? Registrar { get; set; }

    /// <summary>Registration creation date when available.</summary>
    public DateTimeOffset? CreatedAtUtc { get; set; }

    /// <summary>Registration update date when available.</summary>
    public DateTimeOffset? UpdatedAtUtc { get; set; }

    /// <summary>Registration expiration date when available.</summary>
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    /// <summary>Days from snapshot capture to expiry.</summary>
    public int? DaysToExpiry { get; set; }

    /// <summary>Normalized registration status tokens.</summary>
    public List<string> Statuses { get; set; } = new();

    /// <summary>Name servers from registration evidence when available.</summary>
    public List<string> NameServers { get; set; } = new();
}

/// <summary>
/// DNS infrastructure fields that are useful to portfolio storage.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainDnsPortfolioSummary {
    /// <summary>Authoritative name servers.</summary>
    public List<string> NameServers { get; set; } = new();

    /// <summary>MX hostnames.</summary>
    public List<string> MxHosts { get; set; } = new();

    /// <summary>A records or observed IPv4 values.</summary>
    public List<string> IPv4Addresses { get; set; } = new();

    /// <summary>AAAA records or observed IPv6 values.</summary>
    public List<string> IPv6Addresses { get; set; } = new();

    /// <summary>Whether DNSSEC evidence indicates signing or a valid chain.</summary>
    public bool? DnssecEnabled { get; set; }

    /// <summary>Whether CAA records are present.</summary>
    public bool? CaaPresent { get; set; }
}

/// <summary>
/// Certificate fields that are useful to portfolio storage.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainCertificatePortfolioSummary {
    /// <summary>Certificate fingerprint or thumbprint.</summary>
    public string? Fingerprint { get; set; }

    /// <summary>Certificate subject.</summary>
    public string? Subject { get; set; }

    /// <summary>Certificate issuer.</summary>
    public string? Issuer { get; set; }

    /// <summary>Certificate validity start.</summary>
    public DateTimeOffset? NotBeforeUtc { get; set; }

    /// <summary>Certificate validity end.</summary>
    public DateTimeOffset? NotAfterUtc { get; set; }

    /// <summary>Days from snapshot capture to certificate expiry.</summary>
    public int? DaysToExpiry { get; set; }

    /// <summary>Whether certificate evidence indicates a valid certificate.</summary>
    public bool? Valid { get; set; }

    /// <summary>Whether certificate evidence indicates hostname match.</summary>
    public bool? HostnameMatch { get; set; }
}

/// <summary>
/// Mail posture fields that are useful to portfolio storage.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainMailPortfolioSummary {
    /// <summary>MX hostnames.</summary>
    public List<string> MxHosts { get; set; } = new();

    /// <summary>Primary detected mail provider, when available.</summary>
    public string? Provider { get; set; }

    /// <summary>SPF record value.</summary>
    public string? SpfRecord { get; set; }

    /// <summary>SPF all mechanism.</summary>
    public string? SpfAllMechanism { get; set; }

    /// <summary>DMARC record value.</summary>
    public string? DmarcRecord { get; set; }

    /// <summary>DMARC policy.</summary>
    public string? DmarcPolicy { get; set; }

    /// <summary>MTA-STS mode.</summary>
    public string? MtaStsMode { get; set; }

    /// <summary>TLS-RPT record value.</summary>
    public string? TlsRptRecord { get; set; }
}

/// <summary>
/// Website and HTTP posture fields that are useful to portfolio storage.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainWebsitePortfolioSummary {
    /// <summary>HTTP status code when available.</summary>
    public int? StatusCode { get; set; }

    /// <summary>Final URL after redirects when available.</summary>
    public string? FinalUrl { get; set; }

    /// <summary>Whether HTTPS was used or required by the observed endpoint.</summary>
    public bool? UsesHttps { get; set; }

    /// <summary>Whether security.txt evidence is present.</summary>
    public bool? SecurityTxtPresent { get; set; }

    /// <summary>Whether robots.txt evidence is present.</summary>
    public bool? RobotsTxtPresent { get; set; }
}

/// <summary>
/// A check-oriented evidence section inside a <see cref="DomainPortfolioSnapshot"/>.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioSection {
    /// <summary>Stable section key, normally a <see cref="HealthCheckType"/> name.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Human-readable section name.</summary>
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>High-level area such as DNS, Mail, Web, Security, Identity, or General.</summary>
    public string Area { get; set; } = string.Empty;

    /// <summary>Computed section status based on collected assessments.</summary>
    public string Status { get; set; } = "Unknown";

    /// <summary>Number of warning assessments in this section.</summary>
    public int WarningCount { get; set; }

    /// <summary>Number of error assessments in this section.</summary>
    public int ErrorCount { get; set; }

    /// <summary>Storage-friendly scalar facts extracted from the analysis result.</summary>
    public List<DomainPortfolioFact> Facts { get; set; } = new();

    /// <summary>Assessments that belong to this section.</summary>
    public List<Assessment> Assessments { get; set; } = new();
}

/// <summary>
/// A stable scalar value captured from an analysis result.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioFact {
    /// <summary>Stable fact key within the section.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Human-readable fact label.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Normalized string value. Collections are joined deterministically.</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>Value kind used by consumers that want typed storage columns.</summary>
    public DomainPortfolioFactKind Kind { get; set; } = DomainPortfolioFactKind.String;
}

/// <summary>
/// Storage-oriented type hint for a portfolio snapshot fact.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum DomainPortfolioFactKind {
    /// <summary>Text value.</summary>
    String,

    /// <summary>Boolean value.</summary>
    Boolean,

    /// <summary>Numeric value.</summary>
    Number,

    /// <summary>Date or date-time value.</summary>
    DateTime,

    /// <summary>Time span value.</summary>
    Duration,

    /// <summary>Deterministically joined scalar collection.</summary>
    Collection
}

/// <summary>
/// Classification of a portfolio snapshot change.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum DomainPortfolioChangeKind {
    /// <summary>A section or fact appears only in the current snapshot.</summary>
    Added,

    /// <summary>A section or fact appears only in the previous snapshot.</summary>
    Removed,

    /// <summary>A section or fact exists in both snapshots but has a different value.</summary>
    Changed
}

/// <summary>
/// Deterministic change row between two portfolio snapshots.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioChange {
    /// <summary>Stable change key.</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>Type of change.</summary>
    public DomainPortfolioChangeKind Kind { get; set; }

    /// <summary>Section key where the change occurred.</summary>
    public string SectionKey { get; set; } = string.Empty;

    /// <summary>Fact key when the change is fact-scoped.</summary>
    public string? FactKey { get; set; }

    /// <summary>Previous normalized value, if any.</summary>
    public string? PreviousValue { get; set; }

    /// <summary>Current normalized value, if any.</summary>
    public string? CurrentValue { get; set; }
}

/// <summary>
/// Change set produced by comparing two portfolio snapshots.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed class DomainPortfolioChangeSet {
    /// <summary>Previous snapshot subject.</summary>
    public string PreviousSubject { get; set; } = string.Empty;

    /// <summary>Current snapshot subject.</summary>
    public string CurrentSubject { get; set; } = string.Empty;

    /// <summary>Previous snapshot capture time.</summary>
    public DateTimeOffset PreviousCapturedAtUtc { get; set; }

    /// <summary>Current snapshot capture time.</summary>
    public DateTimeOffset CurrentCapturedAtUtc { get; set; }

    /// <summary>Detected changes.</summary>
    public List<DomainPortfolioChange> Changes { get; set; } = new();
}
