namespace DomainDetective;

/// <summary>
/// Represents the various health checks that can be performed on a domain.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public enum HealthCheckType {
    /// <summary>Perform a DMARC policy check.</summary>
    DMARC,
    /// <summary>Verify the SPF record.</summary>
    SPF,
    /// <summary>Validate DKIM configuration.</summary>
    DKIM,
    /// <summary>Check MX records.</summary>
    MX,
    /// <summary>Validate PTR records for MX hosts.</summary>
    REVERSEDNS,
    /// <summary>Confirm PTR hostnames resolve back to the originating IP.</summary>
    FCRDNS,
    /// <summary>Inspect CAA records.</summary>
    CAA,
    /// <summary>Verify NS records.</summary>
    NS,
    /// <summary>Verify parent zone delegation.</summary>
    DELEGATION,
    /// <summary>Attempt a zone transfer.</summary>
    ZONETRANSFER,
    /// <summary>Validate DANE information.</summary>
    DANE,
    /// <summary>Query S/MIMEA records.</summary>
    SMIMEA,
    /// <summary>Check DNSBL listings.</summary>
    DNSBL,
    /// <summary>Validate DNSSEC configuration.</summary>
    DNSSEC,
    /// <summary>Check MTA-STS policy.</summary>
    MTASTS,
    /// <summary>Check TLS-RPT configuration.</summary>
    TLSRPT,
    /// <summary>Validate BIMI records.</summary>
    BIMI,
    /// <summary>Check Autodiscover configuration.</summary>
    AUTODISCOVER,
    /// <summary>Inspect certificate records.</summary>
    CERT,
    /// <summary>Check for security.txt presence.</summary>
    SECURITYTXT,
    /// <summary>Inspect SOA records.</summary>
    SOA,
    /// <summary>Detect open SMTP relay.</summary>
    OPENRELAY,
    /// <summary>Validate STARTTLS support.</summary>
    STARTTLS,
    /// <summary>Verify SMTP TLS configuration.</summary>
    SMTPTLS,
    /// <summary>Verify IMAP TLS configuration.</summary>
    IMAPTLS,
    /// <summary>Verify POP3 TLS configuration.</summary>
    POP3TLS,
    /// <summary>Capture SMTP banner information.</summary>
    SMTPBANNER,
    /// <summary>Enumerate SMTP AUTH mechanisms.</summary>
    SMTPAUTH,
    /// <summary>Perform HTTP checks.</summary>
    HTTP,
    /// <summary>Validate HPKP configuration.</summary>
    HPKP,
    /// <summary>Query contact TXT record.</summary>
    CONTACT,
    /// <summary>Parse message headers.</summary>
    MESSAGEHEADER,
    /// <summary>Validate ARC headers.</summary>
    ARC,
    /// <summary>Detect dangling CNAME records.</summary>
    DANGLINGCNAME,
    /// <summary>Analyze DNS record TTL values.</summary>
    TTL,
    /// <summary>Test common service ports for availability.</summary>
    PORTAVAILABILITY,
    /// <summary>Scan a host for open TCP and UDP ports.</summary>
    PORTSCAN,
    /// <summary>List domains hosted on the same IP address.</summary>
    IPNEIGHBOR,
    /// <summary>Validate RPKI origins for domain IP addresses.</summary>
    RPKI,
    /// <summary>Analyze DNS logs for tunneling patterns.</summary>
    DNSTUNNELING,
    /// <summary>Check for typosquatting domains.</summary>
    TYPOSQUATTING,
    /// <summary>Query reputation services for threats.</summary>
    THREATINTEL,
    /// <summary>Detect wildcard DNS responses.</summary>
    WILDCARDDNS,
    /// <summary>Test EDNS support on name servers.</summary>
    EDNSSUPPORT,
    /// <summary>Measure SMTP connection and banner latency.</summary>
    MAILLATENCY,
    /// <summary>Detect CNAMEs pointing to flattening services.</summary>
    FLATTENINGSERVICE
}
