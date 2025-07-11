using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Provides descriptions for each <see cref="HealthCheckType"/>.
/// </summary>
public static class CheckDescriptions {
    private static readonly IReadOnlyDictionary<HealthCheckType, CheckDescription> _map =
        new Dictionary<HealthCheckType, CheckDescription> {
            // Verify DMARC
            [HealthCheckType.DMARC] = new(
                "Verify DMARC policy.",
                "https://datatracker.ietf.org/doc/html/rfc7489",
                "Publish a valid DMARC record."),
            // Verify SPF
            [HealthCheckType.SPF] = new(
                "Verify SPF record.",
                "https://datatracker.ietf.org/doc/html/rfc7208",
                "Add or correct the SPF TXT record."),
            // Verify DKIM
            [HealthCheckType.DKIM] = new(
                "Verify DKIM configuration.",
                "https://datatracker.ietf.org/doc/html/rfc6376",
                "Ensure DKIM selectors have valid keys."),
            // Verify MX Records
            [HealthCheckType.MX] = new(
                "Verify MX records.",
                "https://datatracker.ietf.org/doc/html/rfc5321",
                "Create valid MX records and order them properly."),
            // Verify reverse DNS (PTR)
            [HealthCheckType.REVERSEDNS] = new(
                "Verify reverse DNS (PTR).",
                "https://datatracker.ietf.org/doc/html/rfc1035",
                "Publish reverse DNS matching MX hostnames."),
            // Verify forward-confirmed reverse DNS (FCrDNS)
            [HealthCheckType.FCRDNS] = new(
                "Verify forward-confirmed reverse DNS (FCrDNS).",
                "https://datatracker.ietf.org/doc/html/rfc1912",
                "Ensure A/AAAA records match the reverse DNS."),
            // Verify CAA
            [HealthCheckType.CAA] = new(
                "Verify CAA records.",
                "https://datatracker.ietf.org/doc/html/rfc6844",
                "Configure allowed certificate authorities."),
            // Verify NS Records
            [HealthCheckType.NS] = new(
                "Verify NS records.",
                null,
                "Publish authoritative name servers."),
            // Verify Delegation (parent NS and glue consistency)
            [HealthCheckType.DELEGATION] = new(
                "Verify delegation (parent NS and glue consistency).",
                null,
                "Ensure NS and glue data match the child zone."),
            // Attempt Zone Transfer
            [HealthCheckType.ZONETRANSFER] = new(
                "Attempt a zone transfer.",
                null,
                "Restrict AXFR to authenticated clients."),
            // Verify DANE/TLSA (HTTPS on port 443 by default)
            [HealthCheckType.DANE] = new(
                "Verify DANE/TLSA.",
                "https://datatracker.ietf.org/doc/html/rfc6698",
                "Provide TLSA records for services."),
            [HealthCheckType.SMIMEA] = new(
                "Query S/MIMEA records.",
                "https://www.rfc-editor.org/rfc/rfc8162",
                "Publish SMIMEA records for user certificates."),
            // Verify Blacklist (DNSBL)
            [HealthCheckType.DNSBL] = new(
                "Verify blacklist (DNSBL).",
                null,
                "Request delisting if blacklisted."),
            // Verify DNSSEC
            [HealthCheckType.DNSSEC] = new(
                "Verify DNSSEC.",
                null,
                "Sign zones and publish DS records."),
            // Verify MTA-STS
            [HealthCheckType.MTASTS] = new(
                "Verify MTA-STS.",
                null,
                "Publish a valid MTA-STS policy."),
            // Verify TLS-RPT
            [HealthCheckType.TLSRPT] = new(
                "Verify TLS-RPT.",
                "https://datatracker.ietf.org/doc/html/rfc8460",
                "Add a TLSRPT record with valid rua addresses."),
            // Verify BIMI
            [HealthCheckType.BIMI] = new(
                "Verify BIMI records.",
                null,
                "Provide a valid BIMI record and hosted logo."),
            // Verify Autodiscover
            [HealthCheckType.AUTODISCOVER] = new(
                "Verify Autodiscover configuration.",
                null,
                "Publish SRV and CNAME records for Autodiscover."),
            // Verify Certificate
            [HealthCheckType.CERT] = new(
                "Verify website certificate.",
                null,
                "Ensure certificates are valid and not expired."),
            // Verify SecurityTXT
            [HealthCheckType.SECURITYTXT] = new(
                "Verify SecurityTXT.",
                null,
                "Host a valid security.txt file."),
            // Verify SOA Records
            [HealthCheckType.SOA] = new(
                "Verify SOA records.",
                null,
                "Publish correct start of authority details."),
            // Verify Open Relay (SMTP)
            [HealthCheckType.OPENRELAY] = new(
                "Verify open relay (SMTP).",
                null,
                "Disable unauthenticated relaying."),
            // Verify STARTTLS (detect advertisement downgrades)
            [HealthCheckType.STARTTLS] = new(
                "Verify STARTTLS and detect downgrades.",
                null,
                "Enable STARTTLS on mail servers."),
            // Verify SMTP TLS
            [HealthCheckType.SMTPTLS] = new(
                "Verify SMTP TLS configuration.",
                null,
                "Use modern TLS and strong ciphers."),
            // Verify IMAP TLS
            [HealthCheckType.IMAPTLS] = new(
                "Verify IMAP TLS configuration.",
                null,
                "Use modern TLS and strong ciphers."),
            // Verify POP3 TLS
            [HealthCheckType.POP3TLS] = new(
                "Verify POP3 TLS configuration.",
                null,
                "Use modern TLS and strong ciphers."),
            // Verify SMTP Banner
            [HealthCheckType.SMTPBANNER] = new(
                "Verify SMTP banner.",
                null,
                "Verify host name and software identifiers."),
            // Enumerate SMTP AUTH mechanisms
            [HealthCheckType.SMTPAUTH] = new(
                "Enumerate SMTP AUTH mechanisms.",
                null,
                "Enable secure authentication methods and disable weak ones."),
            // Verify Website Connectivity
            [HealthCheckType.HTTP] = new(
                "Verify website connectivity.",
                null,
                "Serve websites over HTTPS and respond correctly."),
            // Verify HPKP
            [HealthCheckType.HPKP] = new(
                "Verify HPKP configuration.",
                null,
                "Remove or update stale HPKP headers."),
            // Query contact TXT record
            [HealthCheckType.CONTACT] = new(
                "Query contact TXT record.",
                null,
                "Publish contact TXT information."),
            // Parse message headers
            [HealthCheckType.MESSAGEHEADER] = new(
                "Parse message headers.",
                null,
                "Inspect headers for anomalies."),
            // Validate ARC headers
            [HealthCheckType.ARC] = new(
                "Validate ARC headers.",
                "https://datatracker.ietf.org/doc/html/rfc8617",
                "Ensure ARC-Seal and ARC-Authentication-Results align."),
            // Check for dangling CNAME records
            [HealthCheckType.DANGLINGCNAME] = new(
                "Check for dangling CNAME records.",
                null,
                "Remove or update broken CNAME targets."),
            // Analyze DNS TTL
            [HealthCheckType.TTL] = new(
                "Analyze DNS TTL.",
                null,
                "Adjust TTLs within recommended ranges."),
            // Test common service ports for availability
            [HealthCheckType.PORTAVAILABILITY] = new(
                "Test common service ports for availability.",
                null,
                "Ensure required services accept connections."),
            [HealthCheckType.PORTSCAN] = new(
                "Scan a host for open TCP and UDP ports.",
                null,
                "Harden or disable unnecessary services."),
            // List IP neighbors via reverse/passive DNS
            [HealthCheckType.IPNEIGHBOR] = new(
                "List IP neighbors via reverse or passive DNS.",
                null,
                "Investigate shared hosting risks."),
            [HealthCheckType.RPKI] = new(
                "Validate RPKI origins for domain IPs.",
                "https://rpki.readthedocs.io/",
                "Ensure announced prefixes match valid ROAs."),
            // Detect DNS tunneling from logs
            [HealthCheckType.DNSTUNNELING] = new(
                "Detect DNS tunneling from logs.",
                null,
                "Inspect queries for potential tunneling."),
            // Check for typosquatting domains
            [HealthCheckType.TYPOSQUATTING] = new(
                "Check for typosquatting domains.",
                null,
                "Monitor and register common look-alike domains."),
            // Query reputation services for threats
            [HealthCheckType.THREATINTEL] = new(
                "Query reputation services for threats.",
                null,
                "Review listed threats and request delisting"),
            // Detect wildcard DNS catch-all
            [HealthCheckType.WILDCARDDNS] = new(
                "Detect wildcard DNS catch-all.",
                null,
                "Remove or adjust catch-all DNS entries."),
            // Verify EDNS support
            [HealthCheckType.EDNSSUPPORT] = new(
                "Verify EDNS support.",
                null,
                "Ensure name servers respond to EDNS queries."),
            // Detect CNAME flattening services (e.g., Cloudflare)
            [HealthCheckType.FLATTENINGSERVICE] = new(
                "Detect CNAME flattening services.",
                null,
                "Review CNAME targets and consider removing provider-specific aliases.")
        };

    /// <summary>Gets the description for the specified check type.</summary>
    /// <param name="type">Health check type.</param>
    /// <returns>The description if available; otherwise <c>null</c>.</returns>
    public static CheckDescription? Get(HealthCheckType type) =>
        _map.TryGetValue(type, out var desc) ? desc : null;
}
