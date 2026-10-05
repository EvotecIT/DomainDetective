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
        HealthCheckType.CONTACT,
        HealthCheckType.ROBOTS,
        HealthCheckType.NTP,
        HealthCheckType.FLATTENINGSERVICE
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

    /// <summary>
    /// Chapters in display order. Every chapter belongs to one area; a report shows an area's chapters in this order and
    /// leaves out the ones with no checks.
    /// </summary>
    public static IReadOnlyList<AssessmentChapter> Chapters { get; } = new[] {
        new AssessmentChapter("sender-authentication", "Sender authentication", AnalysisArea.Mail,
            "Who may send mail as the domain, and what receivers do with mail that fails."),
        new AssessmentChapter("mail-transport", "Transport security", AnalysisArea.Mail,
            "Where mail is delivered and whether it travels encrypted."),
        new AssessmentChapter("mail-servers", "Mail servers", AnalysisArea.Mail,
            "How the mail servers present themselves, authenticate and respond."),
        new AssessmentChapter("mail-profile", "Mail profile", AnalysisArea.Mail,
            "Whether the domain sends or receives mail at all."),
        new AssessmentChapter("name-servers", "Delegation and name servers", AnalysisArea.DNS,
            "Whether the zone is delegated correctly and its name servers answer consistently."),
        new AssessmentChapter("dns-security", "DNS security", AnalysisArea.DNS,
            "Whether answers can be forged, records hijacked or the servers abused."),
        new AssessmentChapter("dns-records", "Records", AnalysisArea.DNS,
            "Addresses, reverse names and how long answers are cached."),
        new AssessmentChapter("dns-inventory", "Inventory", AnalysisArea.DNS,
            "Subdomains and records found for the domain."),
        new AssessmentChapter("web-tls", "Certificates and TLS", AnalysisArea.Web,
            "The certificate the website serves and its history in certificate logs."),
        new AssessmentChapter("web-security", "Web security", AnalysisArea.Web,
            "Security headers, exposed directories and a published security contact."),
        new AssessmentChapter("web-site", "Site and discovery", AnalysisArea.Web,
            "Whether the site answers and what it publishes for crawlers and agents."),
        new AssessmentChapter("reputation", "Reputation", AnalysisArea.Security,
            "Block lists, threat feeds and look-alike domains."),
        new AssessmentChapter("network-exposure", "Network exposure", AnalysisArea.Security,
            "Open ports and services reachable from the internet."),
        new AssessmentChapter("addresses", "Addresses and routing", AnalysisArea.Security,
            "Who owns the addresses, what else runs on them and whether routes are signed."),
        new AssessmentChapter("registration", "Registration and contact", AnalysisArea.Security,
            "Registration data and published contacts."),
        new AssessmentChapter("identity", "Identity providers", AnalysisArea.Identity,
            "Sign-in providers and cloud tenants the domain uses."),
        new AssessmentChapter("general", "Other checks", AnalysisArea.General,
            "Checks outside the areas above.")
    };

    private static readonly Dictionary<HealthCheckType, string> ChapterKeys = new() {
        [HealthCheckType.SPF] = "sender-authentication",
        [HealthCheckType.SPFFLATTENED] = "sender-authentication",
        [HealthCheckType.DKIM] = "sender-authentication",
        [HealthCheckType.DMARC] = "sender-authentication",
        [HealthCheckType.ARC] = "sender-authentication",
        [HealthCheckType.BIMI] = "sender-authentication",
        [HealthCheckType.MX] = "mail-transport",
        [HealthCheckType.STARTTLS] = "mail-transport",
        [HealthCheckType.SMTPTLS] = "mail-transport",
        [HealthCheckType.MTASTS] = "mail-transport",
        [HealthCheckType.TLSRPT] = "mail-transport",
        [HealthCheckType.SMIMEA] = "mail-transport",
        [HealthCheckType.SMTPBANNER] = "mail-servers",
        [HealthCheckType.SMTPAUTH] = "mail-servers",
        [HealthCheckType.OPENRELAY] = "mail-servers",
        [HealthCheckType.IMAPTLS] = "mail-servers",
        [HealthCheckType.POP3TLS] = "mail-servers",
        [HealthCheckType.MAILLATENCY] = "mail-servers",
        [HealthCheckType.AUTODISCOVER] = "mail-servers",
        [HealthCheckType.MAILCLASSIFICATION] = "mail-profile",
        [HealthCheckType.NS] = "name-servers",
        [HealthCheckType.SOA] = "name-servers",
        [HealthCheckType.DELEGATION] = "name-servers",
        [HealthCheckType.EDNSSUPPORT] = "name-servers",
        [HealthCheckType.DNSHEALTH] = "name-servers",
        [HealthCheckType.DNSPROPAGATION] = "name-servers",
        [HealthCheckType.DNSTRACE] = "name-servers",
        [HealthCheckType.DNSSEC] = "dns-security",
        [HealthCheckType.CAA] = "dns-security",
        [HealthCheckType.ZONETRANSFER] = "dns-security",
        [HealthCheckType.OPENRESOLVER] = "dns-security",
        [HealthCheckType.DNSAMPLIFICATION] = "dns-security",
        [HealthCheckType.DANGLINGCNAME] = "dns-security",
        [HealthCheckType.DNSOVERTLS] = "dns-security",
        [HealthCheckType.WILDCARDDNS] = "dns-security",
        [HealthCheckType.TTL] = "dns-records",
        [HealthCheckType.APEXADDRESS] = "dns-records",
        [HealthCheckType.REVERSEDNS] = "dns-records",
        [HealthCheckType.FCRDNS] = "dns-records",
        [HealthCheckType.FLATTENINGSERVICE] = "dns-records",
        [HealthCheckType.SUBDOMAINS] = "dns-inventory",
        [HealthCheckType.DNSINVENTORY] = "dns-inventory",
        [HealthCheckType.CERT] = "web-tls",
        [HealthCheckType.DANE] = "web-tls",
        [HealthCheckType.HPKP] = "web-tls",
        [HealthCheckType.CTTIMELINE] = "web-tls",
        [HealthCheckType.HTTP] = "web-security",
        [HealthCheckType.DIRECTORYEXPOSURE] = "web-security",
        [HealthCheckType.SECURITYTXT] = "web-security",
        [HealthCheckType.WEBSITE] = "web-site",
        [HealthCheckType.ROBOTS] = "web-site",
        [HealthCheckType.SITEMAP] = "web-site",
        [HealthCheckType.AGENTREADINESS] = "web-site",
        [HealthCheckType.DNSBL] = "reputation",
        [HealthCheckType.THREATINTEL] = "reputation",
        [HealthCheckType.THREATFEED] = "reputation",
        [HealthCheckType.TYPOSQUATTING] = "reputation",
        [HealthCheckType.PORTSCAN] = "network-exposure",
        [HealthCheckType.PORTAVAILABILITY] = "network-exposure",
        [HealthCheckType.SNMP] = "network-exposure",
        [HealthCheckType.NTP] = "network-exposure",
        [HealthCheckType.DNSTUNNELING] = "network-exposure",
        [HealthCheckType.RPKI] = "addresses",
        [HealthCheckType.IPNEIGHBOR] = "addresses",
        [HealthCheckType.IPENRICHMENT] = "addresses",
        [HealthCheckType.RDAP] = "registration",
        [HealthCheckType.WHOIS] = "registration",
        [HealthCheckType.CONTACT] = "registration",
        [HealthCheckType.IDENTITYPROVIDER] = "identity",
        [HealthCheckType.MICROSOFT365] = "identity"
    };

    /// <summary>
    /// Chapter a check belongs to. A check without a chapter of its own (or a result that names no check) goes to the
    /// first chapter of its area, or to "Other checks" when the area has none.
    /// </summary>
    public static AssessmentChapter ChapterFor(HealthCheckType? check, AnalysisArea area) {
        if (check.HasValue && ChapterKeys.TryGetValue(check.Value, out string? key)) {
            foreach (AssessmentChapter chapter in Chapters) {
                if (chapter.Key == key) return chapter;
            }
        }
        foreach (AssessmentChapter chapter in Chapters) {
            if (chapter.Area == area) return chapter;
        }
        return Chapters[Chapters.Count - 1];
    }

    /// <summary>
    /// Weighted score of a set of checks (0–100), the same rule used for domain and area scores: scored checks only,
    /// each counted by its weight. Null when none of the checks is scored.
    /// </summary>
    public static int? CombinedScore(IEnumerable<CheckAssessment> checks) {
        int weight = 0;
        double total = 0;
        foreach (CheckAssessment check in checks) {
            if (!check.Scored) continue;
            weight += check.Weight;
            total += (double)check.Score * check.Weight;
        }
        if (weight == 0) return null;
        return (int)Math.Round(total / weight, MidpointRounding.AwayFromZero);
    }

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

/// <summary>
/// A chapter of an analysis area: a named group of related checks, such as "Sender authentication" in Mail. Reports use
/// chapters to group checks under their area; DomainDetectiveNext uses the same chapters for its area pages.
/// </summary>
public sealed class AssessmentChapter {
    /// <summary>Creates a chapter.</summary>
    public AssessmentChapter(string key, string title, AnalysisArea area, string question) {
        Key = key;
        Title = title;
        Area = area;
        Question = question;
    }

    /// <summary>Stable key, unique across areas (for example <c>sender-authentication</c>).</summary>
    public string Key { get; }

    /// <summary>Display title.</summary>
    public string Title { get; }

    /// <summary>Area the chapter belongs to.</summary>
    public AnalysisArea Area { get; }

    /// <summary>What the chapter answers, in one sentence.</summary>
    public string Question { get; }
}
