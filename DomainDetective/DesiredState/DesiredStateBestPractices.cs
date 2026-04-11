namespace DomainDetective.DesiredState;

/// <summary>Provides desired state best practices functionality.</summary>
public static class DesiredStateBestPractices {
    /// <summary>Represents the recommended checks value.</summary>
    public static readonly HealthCheckType[] RecommendedChecks = new[] {
        HealthCheckType.DMARC,
        HealthCheckType.SPF,
        HealthCheckType.DKIM,
        HealthCheckType.MTASTS,
        HealthCheckType.TLSRPT,
        HealthCheckType.BIMI,
        HealthCheckType.MX,
        HealthCheckType.AUTODISCOVER,
        HealthCheckType.REVERSEDNS,
        HealthCheckType.FCRDNS,
        HealthCheckType.NS,
        HealthCheckType.DELEGATION,
        HealthCheckType.ZONETRANSFER,
        HealthCheckType.DANGLINGCNAME,
        HealthCheckType.CAA,
        HealthCheckType.DNSSEC,
        HealthCheckType.SOA,
        HealthCheckType.DANE,
        HealthCheckType.DNSBL,
        HealthCheckType.DNSHEALTH,
        HealthCheckType.APEXADDRESS,
        HealthCheckType.RPKI,
        HealthCheckType.EDNSSUPPORT,
        HealthCheckType.DNSOVERTLS,
        HealthCheckType.FLATTENINGSERVICE,
        HealthCheckType.WILDCARDDNS,
        HealthCheckType.TTL,
        HealthCheckType.SECURITYTXT,
        HealthCheckType.ROBOTS,
        HealthCheckType.OPENRESOLVER
    };

    /// <summary>Represents the active mail checks value.</summary>
    public static readonly HealthCheckType[] ActiveMailChecks = new[] {
        HealthCheckType.STARTTLS,
        HealthCheckType.SMTPTLS,
        HealthCheckType.IMAPTLS,
        HealthCheckType.POP3TLS,
        HealthCheckType.SMTPBANNER,
        HealthCheckType.SMTPAUTH,
        HealthCheckType.MAILLATENCY,
        HealthCheckType.OPENRELAY
    };
}
