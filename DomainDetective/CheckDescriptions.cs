using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Provides descriptions for each <see cref="HealthCheckType"/>.
/// </summary>
public static class CheckDescriptions {
    private static readonly IReadOnlyDictionary<HealthCheckType, CheckDescription> _map =
        new Dictionary<HealthCheckType, CheckDescription> {
            [HealthCheckType.DMARC] = new(
                "Perform a DMARC policy check.",
                "https://datatracker.ietf.org/doc/html/rfc7489",
                "Publish a valid DMARC record."),
            [HealthCheckType.SPF] = new(
                "Verify the SPF record.",
                "https://datatracker.ietf.org/doc/html/rfc7208",
                "Add or correct the SPF TXT record."),
            [HealthCheckType.DKIM] = new(
                "Validate DKIM configuration.",
                "https://datatracker.ietf.org/doc/html/rfc6376",
                "Ensure DKIM selectors have valid keys."),
            [HealthCheckType.MX] = new(
                "Check MX records.",
                "https://datatracker.ietf.org/doc/html/rfc5321",
                "Create valid MX records and order them properly."),
            [HealthCheckType.REVERSEDNS] = new(
                "Verify PTR records for MX hosts.",
                "https://datatracker.ietf.org/doc/html/rfc1035",
                "Publish reverse DNS matching MX hostnames."),
            [HealthCheckType.FCRDNS] = new(
                "Confirm PTR hostnames resolve back to the original IP.",
                "https://datatracker.ietf.org/doc/html/rfc1912",
                "Ensure A/AAAA records match the reverse DNS."),
            [HealthCheckType.CAA] = new(
                "Inspect CAA records.",
                "https://datatracker.ietf.org/doc/html/rfc6844",
                "Configure allowed certificate authorities."),
            [HealthCheckType.NS] = new(
                "Verify NS records.",
                null,
                "Publish authoritative name servers."),
            [HealthCheckType.DELEGATION] = new(
                "Verify parent zone delegation records.",
                null,
                "Ensure NS and glue data match the child zone."),
            [HealthCheckType.ZONETRANSFER] = new(
                "Attempt a zone transfer.",
                null,
                "Restrict AXFR to authenticated clients."),
            [HealthCheckType.DANE] = new(
                "Validate DANE information.",
                "https://datatracker.ietf.org/doc/html/rfc6698",
                "Provide TLSA records for services."),
            [HealthCheckType.DNSBL] = new(
                "Check DNSBL listings.",
                null,
                "Request delisting if blacklisted."),
            [HealthCheckType.DNSSEC] = new(
                "Validate DNSSEC configuration.",
                null,
                "Sign zones and publish DS records."),
            [HealthCheckType.MTASTS] = new(
                "Check MTA-STS policy.",
                null,
                "Publish a valid MTA-STS policy."),
            [HealthCheckType.TLSRPT] = new(
                "Check TLS-RPT configuration.",
                "https://datatracker.ietf.org/doc/html/rfc8460",
                "Add a TLSRPT record with valid rua addresses."),
            [HealthCheckType.BIMI] = new(
                "Validate BIMI records.",
                null,
                "Provide a valid BIMI record and hosted logo."),
            [HealthCheckType.AUTODISCOVER] = new(
                "Check Autodiscover configuration.",
                null,
                "Publish SRV and CNAME records for Autodiscover."),
            [HealthCheckType.CERT] = new(
                "Inspect certificate records.",
                null,
                "Ensure certificates are valid and not expired."),
            [HealthCheckType.SECURITYTXT] = new(
                "Check for security.txt presence.",
                null,
                "Host a valid security.txt file."),
            [HealthCheckType.SOA] = new(
                "Inspect SOA records.",
                null,
                "Publish correct start of authority details."),
            [HealthCheckType.OPENRELAY] = new(
                "Detect open SMTP relay.",
                null,
                "Disable unauthenticated relaying."),
            [HealthCheckType.STARTTLS] = new(
                "Validate STARTTLS support and detect advertisement downgrades.",
                null,
                "Enable STARTTLS on mail servers."),
            [HealthCheckType.SMTPTLS] = new(
                "Verify SMTP TLS configuration.",
                null,
                "Use modern TLS and strong ciphers."),
            [HealthCheckType.SMTPBANNER] = new(
                "Capture SMTP banner information.",
                null,
                "Verify host name and software identifiers."),
            [HealthCheckType.HTTP] = new(
                "Perform HTTP checks.",
                null,
                "Serve websites over HTTPS and respond correctly."),
            [HealthCheckType.HPKP] = new(
                "Validate HPKP configuration.",
                null,
                "Remove or update stale HPKP headers."),
            [HealthCheckType.CONTACT] = new(
                "Query contact TXT record.",
                null,
                "Publish contact TXT information."),
            [HealthCheckType.MESSAGEHEADER] = new(
                "Parse message headers.",
                null,
                "Inspect headers for anomalies."),
            [HealthCheckType.ARC] = new(
                "Validate ARC headers.",
                "https://datatracker.ietf.org/doc/html/rfc8617",
                "Ensure ARC-Seal and ARC-Authentication-Results align."),
            [HealthCheckType.DANGLINGCNAME] = new(
                "Detect dangling CNAME records.",
                null,
                "Remove or update broken CNAME targets."),
            [HealthCheckType.TTL] = new(
                "Analyze DNS record TTL values.",
                null,
                "Adjust TTLs within recommended ranges."),
            [HealthCheckType.PORTAVAILABILITY] = new(
                "Test common service ports for availability.",
                null,
                "Ensure required services accept connections."),
            [HealthCheckType.IPNEIGHBOR] = new(
                "List domains hosted on the same IP address.",
                null,
                "Investigate shared hosting risks."),
            [HealthCheckType.DNSTUNNELING] = new(
                "Analyze DNS logs for tunneling patterns.",
                null,
                "Inspect queries for potential tunneling."),
            [HealthCheckType.TYPOSQUATTING] = new(
                "Check for typosquatting domains.",
                null,
                "Monitor and register common look-alike domains.")
        };

    /// <summary>Gets the description for the specified check type.</summary>
    /// <param name="type">Health check type.</param>
    /// <returns>The description if available; otherwise <c>null</c>.</returns>
    public static CheckDescription? Get(HealthCheckType type) =>
        _map.TryGetValue(type, out var desc) ? desc : null;
}
