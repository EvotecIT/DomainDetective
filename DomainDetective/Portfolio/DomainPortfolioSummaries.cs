using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Compact typed summary projections for common portfolio workflows.
/// </summary>
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
public sealed class DomainDnsPortfolioSummary {
    /// <summary>Authoritative name servers.</summary>
    public List<string> NameServers { get; set; } = new();

    /// <summary>DNS-level MX hostnames, mirrored in the mail summary for mail-focused consumers.</summary>
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
public sealed class DomainMailPortfolioSummary {
    /// <summary>MX hostnames mirrored from <see cref="DomainDnsPortfolioSummary.MxHosts"/> for mail-focused consumers.</summary>
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
