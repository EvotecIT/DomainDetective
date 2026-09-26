using System;
using System.Collections.Generic;

namespace DomainDetective.Reports;

/// <summary>
/// Display names, weights and scoring rules for checks in a <see cref="DomainAssessment"/>.
/// </summary>
public static class DomainAssessmentCatalog {
    private static readonly Dictionary<HealthCheckType, (string Title, string? LongTitle)> Titles = new() {
        [HealthCheckType.DMARC] = ("DMARC", "Domain-based Message Authentication, Reporting and Conformance"),
        [HealthCheckType.SPF] = ("SPF", "Sender Policy Framework"),
        [HealthCheckType.DKIM] = ("DKIM", "DomainKeys Identified Mail"),
        [HealthCheckType.MX] = ("MX", "Mail exchangers"),
        [HealthCheckType.REVERSEDNS] = ("Reverse DNS", "PTR records for mail hosts"),
        [HealthCheckType.FCRDNS] = ("Forward-confirmed reverse DNS", null),
        [HealthCheckType.CAA] = ("CAA", "Certification Authority Authorization"),
        [HealthCheckType.NS] = ("NS", "Name servers"),
        [HealthCheckType.DELEGATION] = ("Delegation", "Parent zone delegation"),
        [HealthCheckType.ZONETRANSFER] = ("Zone transfer", "AXFR exposure"),
        [HealthCheckType.DANE] = ("DANE", "DNS-based Authentication of Named Entities"),
        [HealthCheckType.SMIMEA] = ("SMIMEA", "S/MIME certificate association"),
        [HealthCheckType.DNSBL] = ("DNSBL", "DNS block lists"),
        [HealthCheckType.DNSSEC] = ("DNSSEC", "DNS Security Extensions"),
        [HealthCheckType.MTASTS] = ("MTA-STS", "Mail Transfer Agent Strict Transport Security"),
        [HealthCheckType.TLSRPT] = ("TLS-RPT", "SMTP TLS reporting"),
        [HealthCheckType.BIMI] = ("BIMI", "Brand Indicators for Message Identification"),
        [HealthCheckType.AUTODISCOVER] = ("Autodiscover", "Mail client autoconfiguration"),
        [HealthCheckType.CERT] = ("Certificate", "Web server certificate"),
        [HealthCheckType.SECURITYTXT] = ("security.txt", "Security contact file"),
        [HealthCheckType.ROBOTS] = ("robots.txt", null),
        [HealthCheckType.SOA] = ("SOA", "Start of authority"),
        [HealthCheckType.OPENRELAY] = ("Open relay", "SMTP relay exposure"),
        [HealthCheckType.OPENRESOLVER] = ("Open resolver", "Recursive DNS exposure"),
        [HealthCheckType.STARTTLS] = ("STARTTLS", "Opportunistic TLS on SMTP"),
        [HealthCheckType.SMTPTLS] = ("SMTP TLS", "TLS on SMTP"),
        [HealthCheckType.IMAPTLS] = ("IMAP TLS", "TLS on IMAP"),
        [HealthCheckType.POP3TLS] = ("POP3 TLS", "TLS on POP3"),
        [HealthCheckType.SMTPBANNER] = ("SMTP banner", null),
        [HealthCheckType.SMTPAUTH] = ("SMTP AUTH", "SMTP authentication mechanisms"),
        [HealthCheckType.HTTP] = ("HTTP", "Web security headers and transport"),
        [HealthCheckType.HPKP] = ("HPKP", "HTTP public key pinning"),
        [HealthCheckType.CONTACT] = ("Contact", "Contact information"),
        [HealthCheckType.MESSAGEHEADER] = ("Message header", null),
        [HealthCheckType.ARC] = ("ARC", "Authenticated Received Chain"),
        [HealthCheckType.DANGLINGCNAME] = ("Dangling CNAME", "Subdomain takeover exposure"),
        [HealthCheckType.TTL] = ("TTL", "Record time-to-live"),
        [HealthCheckType.PORTAVAILABILITY] = ("Port availability", null),
        [HealthCheckType.PORTSCAN] = ("Port scan", null),
        [HealthCheckType.SNMP] = ("SNMP", null),
        [HealthCheckType.IPNEIGHBOR] = ("IP neighbours", "Other domains on the same addresses"),
        [HealthCheckType.IPENRICHMENT] = ("IP enrichment", "Address ownership and location"),
        [HealthCheckType.RPKI] = ("RPKI", "Resource Public Key Infrastructure"),
        [HealthCheckType.DNSTUNNELING] = ("DNS tunneling", null),
        [HealthCheckType.TYPOSQUATTING] = ("Typosquatting", "Look-alike domains"),
        [HealthCheckType.THREATINTEL] = ("Threat intelligence", null),
        [HealthCheckType.THREATFEED] = ("Threat feeds", null),
        [HealthCheckType.WILDCARDDNS] = ("Wildcard DNS", null),
        [HealthCheckType.EDNSSUPPORT] = ("EDNS support", null),
        [HealthCheckType.DNSHEALTH] = ("DNS health", null),
        [HealthCheckType.MAILLATENCY] = ("Mail latency", null),
        [HealthCheckType.FLATTENINGSERVICE] = ("Flattening service", null),
        [HealthCheckType.RDAP] = ("Registration", "RDAP registration data"),
        [HealthCheckType.DIRECTORYEXPOSURE] = ("Directory exposure", null),
        [HealthCheckType.NTP] = ("NTP", null),
        [HealthCheckType.WEBSITE] = ("Website", null),
        [HealthCheckType.WHOIS] = ("WHOIS", null),
        [HealthCheckType.APEXADDRESS] = ("Apex address", "A and AAAA records at the zone apex"),
        [HealthCheckType.SPFFLATTENED] = ("SPF flattened", "Resolved SPF addresses"),
        [HealthCheckType.MAILCLASSIFICATION] = ("Mail classification", "Sending and receiving role"),
        [HealthCheckType.SUBDOMAINS] = ("Subdomains", null),
        [HealthCheckType.DNSINVENTORY] = ("DNS inventory", null),
        [HealthCheckType.DNSTRACE] = ("DNS trace", "Resolution path"),
        [HealthCheckType.CTTIMELINE] = ("CT timeline", "Certificate Transparency history"),
        [HealthCheckType.DNSPROPAGATION] = ("DNS propagation", null),
        [HealthCheckType.DNSAMPLIFICATION] = ("DNS amplification", null),
        [HealthCheckType.DNSOVERTLS] = ("DNS over TLS", null),
        [HealthCheckType.IDENTITYPROVIDER] = ("Identity provider", null),
        [HealthCheckType.MICROSOFT365] = ("Microsoft 365", "Tenant and workload footprint"),
        [HealthCheckType.SITEMAP] = ("Sitemap", null),
        [HealthCheckType.AGENTREADINESS] = ("Agent readiness", "Machine-readable discovery endpoints")
    };

    // Inventory and discovery checks describe the domain rather than grade it. Their warnings are still reported.
    private static readonly HashSet<HealthCheckType> Informational = new() {
        HealthCheckType.SUBDOMAINS,
        HealthCheckType.DNSINVENTORY,
        HealthCheckType.DNSTRACE,
        HealthCheckType.DNSPROPAGATION,
        HealthCheckType.CTTIMELINE,
        HealthCheckType.IPENRICHMENT,
        HealthCheckType.IPNEIGHBOR,
        HealthCheckType.TYPOSQUATTING,
        HealthCheckType.MAILCLASSIFICATION,
        HealthCheckType.MICROSOFT365,
        HealthCheckType.IDENTITYPROVIDER,
        HealthCheckType.WHOIS,
        HealthCheckType.RDAP,
        HealthCheckType.SITEMAP,
        HealthCheckType.AGENTREADINESS,
        HealthCheckType.SPFFLATTENED,
        HealthCheckType.MAILLATENCY,
        HealthCheckType.CONTACT
    };

    // Mail authentication decides whether a domain can be spoofed, so it weighs more than other checks.
    private static readonly Dictionary<HealthCheckType, int> Weights = new() {
        [HealthCheckType.SPF] = 2,
        [HealthCheckType.DMARC] = 3,
        [HealthCheckType.DKIM] = 2,
        [HealthCheckType.MX] = 2,
        [HealthCheckType.DNSSEC] = 2
    };

    /// <summary>Areas in display order.</summary>
    public static IReadOnlyList<AnalysisArea> AreaOrder { get; } = new[] {
        AnalysisArea.Mail, AnalysisArea.DNS, AnalysisArea.Web, AnalysisArea.Security, AnalysisArea.Identity, AnalysisArea.General
    };

    /// <summary>Short title and expanded name of a check.</summary>
    public static (string Title, string? LongTitle) TitleFor(HealthCheckType check)
        => Titles.TryGetValue(check, out var title) ? title : (check.ToString(), null);

    /// <summary>Whether a check counts toward the domain score.</summary>
    public static bool IsScored(HealthCheckType check) => !Informational.Contains(check);

    /// <summary>Weight of a check in the domain score.</summary>
    public static int WeightFor(HealthCheckType check) => Weights.TryGetValue(check, out int weight) ? weight : 1;

    /// <summary>
    /// Check score: 100 when it passes, reduced by 15 per warning (not below 50); with errors, 40 for the first, minus 10
    /// per further error and 5 per warning (not below 0).
    /// </summary>
    public static int ScoreFor(int errors, int warnings) {
        if (errors > 0) return Math.Max(0, 40 - 10 * (errors - 1) - 5 * warnings);
        if (warnings > 0) return Math.Max(50, 100 - 15 * warnings);
        return 100;
    }

    /// <summary>Letter grade for a score: A from 90, B from 80, C from 70, D from 60, otherwise F.</summary>
    public static string GradeFor(int? score) => score switch {
        null => "-",
        >= 90 => "A",
        >= 80 => "B",
        >= 70 => "C",
        >= 60 => "D",
        _ => "F"
    };
}
