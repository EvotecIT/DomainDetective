using DomainDetective.Toolbox.Models;

namespace DomainDetective.Toolbox.Services;

public sealed class ToolRegistry {
    private static readonly List<ToolDefinition> _tools = new() {
        // Email Security
        new ToolDefinition {
            Name = "SPF Lookup",
            Slug = "spf",
            Description = "Validate SPF records and check for misconfigurations",
            Category = ToolCategory.EmailSecurity,
            Icon = "shield-check",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "DKIM Lookup",
            Slug = "dkim",
            Description = "Verify DKIM records and key validity",
            Category = ToolCategory.EmailSecurity,
            Icon = "key",
            InputPlaceholder = "example.com",
            SecondaryInputLabel = "Selector",
            SecondaryInputPlaceholder = "default"
        },
        new ToolDefinition {
            Name = "DMARC Lookup",
            Slug = "dmarc",
            Description = "Analyze DMARC policy and reporting configuration",
            Category = ToolCategory.EmailSecurity,
            Icon = "shield",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "MX Lookup",
            Slug = "mx",
            Description = "Check mail exchanger records and priorities",
            Category = ToolCategory.EmailSecurity,
            Icon = "mail",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "MTA-STS Check",
            Slug = "mta-sts",
            Description = "Verify MTA-STS policy for enforced TLS",
            Category = ToolCategory.EmailSecurity,
            Icon = "lock",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },
        new ToolDefinition {
            Name = "TLS-RPT Check",
            Slug = "tls-rpt",
            Description = "Check TLS reporting DNS record configuration",
            Category = ToolCategory.EmailSecurity,
            Icon = "file-text",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "BIMI Lookup",
            Slug = "bimi",
            Description = "Validate BIMI record and brand indicator",
            Category = ToolCategory.EmailSecurity,
            Icon = "image",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },

        // DNS
        new ToolDefinition {
            Name = "DNS Lookup",
            Slug = "dns-lookup",
            Description = "Query DNS records of any type (A, AAAA, CNAME, TXT, etc.)",
            Category = ToolCategory.Dns,
            Icon = "search",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "DNSSEC Check",
            Slug = "dnssec",
            Description = "Validate DNSSEC chain of trust",
            Category = ToolCategory.Dns,
            Icon = "shield",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },
        new ToolDefinition {
            Name = "SOA Lookup",
            Slug = "soa",
            Description = "Check SOA record and zone authority",
            Category = ToolCategory.Dns,
            Icon = "server",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "NS Lookup",
            Slug = "ns",
            Description = "List authoritative nameservers",
            Category = ToolCategory.Dns,
            Icon = "globe",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "DNS Propagation",
            Slug = "dns-propagation",
            Description = "Check DNS propagation across global resolvers",
            Category = ToolCategory.Dns,
            Icon = "radio",
            InputPlaceholder = "example.com"
        },

        // TLS & Certificates
        new ToolDefinition {
            Name = "Certificate Check",
            Slug = "cert-check",
            Description = "Inspect TLS certificate details and chain",
            Category = ToolCategory.TlsCert,
            Icon = "award",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },
        new ToolDefinition {
            Name = "CAA Lookup",
            Slug = "caa",
            Description = "Check Certificate Authority Authorization records",
            Category = ToolCategory.TlsCert,
            Icon = "check-square",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "DANE Check",
            Slug = "dane",
            Description = "Validate DANE/TLSA records",
            Category = ToolCategory.TlsCert,
            Icon = "link",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },

        // Web Security
        new ToolDefinition {
            Name = "HTTP Headers",
            Slug = "http-headers",
            Description = "Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)",
            Category = ToolCategory.WebSecurity,
            Icon = "code",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },
        new ToolDefinition {
            Name = "Security.txt",
            Slug = "security-txt",
            Description = "Check for security.txt disclosure file",
            Category = ToolCategory.WebSecurity,
            Icon = "file-text",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },

        // Registration
        new ToolDefinition {
            Name = "RDAP / WHOIS",
            Slug = "rdap",
            Description = "Query domain registration data via RDAP",
            Category = ToolCategory.Registration,
            Icon = "database",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        },

        // Threat Intel
        new ToolDefinition {
            Name = "DNSBL Check",
            Slug = "dnsbl",
            Description = "Check domain/IP against DNS blacklists",
            Category = ToolCategory.ThreatIntel,
            Icon = "alert-triangle",
            InputPlaceholder = "example.com"
        },
        new ToolDefinition {
            Name = "Dangling CNAME",
            Slug = "dangling-cname",
            Description = "Detect dangling CNAME records vulnerable to takeover",
            Category = ToolCategory.ThreatIntel,
            Icon = "alert-circle",
            InputPlaceholder = "example.com"
        },

        // Subdomain
        new ToolDefinition {
            Name = "CT Subdomain Discovery",
            Slug = "ct-subdomains",
            Description = "Discover subdomains via Certificate Transparency logs",
            Category = ToolCategory.Subdomain,
            Icon = "layers",
            InputPlaceholder = "example.com",
            BrowserCompatible = false
        }
    };

    public IReadOnlyList<ToolDefinition> GetAll() => _tools;

    public ToolDefinition? GetBySlug(string slug) =>
        _tools.FirstOrDefault(t => t.Slug.Equals(slug, StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<ToolDefinition> GetByCategory(ToolCategory category) =>
        _tools.Where(t => t.Category == category).ToList();

    public IReadOnlyList<ToolDefinition> Search(string query) {
        if (string.IsNullOrWhiteSpace(query)) return _tools;
        return _tools.Where(t =>
            t.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            t.Description.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            t.Slug.Contains(query, StringComparison.OrdinalIgnoreCase)
        ).ToList();
    }

    public static string GetCategoryDisplayName(ToolCategory category) => category switch {
        ToolCategory.EmailSecurity => "Email Security",
        ToolCategory.Dns => "DNS",
        ToolCategory.TlsCert => "TLS & Certificates",
        ToolCategory.WebSecurity => "Web Security",
        ToolCategory.Registration => "Registration",
        ToolCategory.ThreatIntel => "Threat Intelligence",
        ToolCategory.Subdomain => "Subdomain Discovery",
        ToolCategory.Network => "Network",
        _ => category.ToString()
    };

    public static string GetCategoryIcon(ToolCategory category) => category switch {
        ToolCategory.EmailSecurity => "mail",
        ToolCategory.Dns => "globe",
        ToolCategory.TlsCert => "lock",
        ToolCategory.WebSecurity => "shield",
        ToolCategory.Registration => "database",
        ToolCategory.ThreatIntel => "alert-triangle",
        ToolCategory.Subdomain => "layers",
        ToolCategory.Network => "wifi",
        _ => "circle"
    };
}
