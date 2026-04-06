using DomainDetective.Toolbox.Models;

namespace DomainDetective.Toolbox.Services;

public sealed class ToolRegistry {
    private static readonly List<ToolDefinition> _tools = new() {
        new ToolDefinition {
            Name = "M365 Tenant Overview",
            Slug = "m365-overview",
            Description = "Aggregate Microsoft 365 tenant, identity, DNS, and mail posture in one DD-backed dashboard",
            Category = ToolCategory.Overview,
            Icon = "building",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            LiteCompatible = true,
            CliExample = "domaindetective check 'example.com'",
            PowerShellExample = "Test-DomainHealth -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.Verify(\"example.com\");"
        },
        new ToolDefinition {
            Name = "Domain Overview",
            Slug = "domain-overview",
            Description = "Aggregate DNS, mail, web, registration, and exposure posture for any domain",
            Category = ToolCategory.Overview,
            Icon = "layout-dashboard",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            LiteCompatible = true,
            CliExample = "domaindetective check 'example.com'",
            PowerShellExample = "Test-DomainHealth -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.Verify(\"example.com\");"
        },

        // Email Security
        new ToolDefinition {
            Name = "SPF Lookup",
            Slug = "spf",
            Description = "Validate SPF records and check for misconfigurations",
            Category = ToolCategory.EmailSecurity,
            Icon = "shield-check",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks SPF",
            PowerShellExample = "Test-DDEmailSpfRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifySPF(\"example.com\");"
        },
        new ToolDefinition {
            Name = "DKIM Lookup",
            Slug = "dkim",
            Description = "Verify DKIM records and key validity",
            Category = ToolCategory.EmailSecurity,
            Icon = "key",
            InputPlaceholder = "example.com",
            SecondaryInputLabel = "Selector (optional)",
            SecondaryInputPlaceholder = "Leave blank to auto-detect",
            CliExample = "domaindetective check 'example.com' --checks DKIM",
            PowerShellExample = "Test-DDEmailDkimRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDKIM(\"example.com\", new[] { \"selector1\" });"
        },
        new ToolDefinition {
            Name = "DMARC Lookup",
            Slug = "dmarc",
            Description = "Analyze DMARC policy and reporting configuration",
            Category = ToolCategory.EmailSecurity,
            Icon = "shield",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DMARC",
            PowerShellExample = "Test-DDEmailDmarcRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDMARC(\"example.com\");"
        },
        new ToolDefinition {
            Name = "MX Lookup",
            Slug = "mx",
            Description = "Check mail exchanger records and priorities",
            Category = ToolCategory.EmailSecurity,
            Icon = "mail",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks MX",
            PowerShellExample = "Test-DDDnsMxRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyMX(\"example.com\");"
        },
        new ToolDefinition {
            Name = "MTA-STS Check",
            Slug = "mta-sts",
            Description = "Verify MTA-STS policy for enforced TLS",
            Category = ToolCategory.EmailSecurity,
            Icon = "lock",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            LiteCompatible = true,
            CliExample = "domaindetective check 'example.com' --checks MTASTS",
            PowerShellExample = "Test-DDEmailMtaSts -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyMTASTS(\"example.com\");"
        },
        new ToolDefinition {
            Name = "TLS-RPT Check",
            Slug = "tls-rpt",
            Description = "Check TLS reporting DNS record configuration",
            Category = ToolCategory.EmailSecurity,
            Icon = "file-text",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks TLSRPT",
            PowerShellExample = "Test-DDEmailTlsRptRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyTLSRPT(\"example.com\");"
        },
        new ToolDefinition {
            Name = "BIMI Lookup",
            Slug = "bimi",
            Description = "Validate BIMI record and brand indicator",
            Category = ToolCategory.EmailSecurity,
            Icon = "image",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks BIMI",
            PowerShellExample = "Test-DDEmailBimiRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyBIMI(\"example.com\");"
        },

        // DNS
        new ToolDefinition {
            Name = "DNS Lookup",
            Slug = "dns-lookup",
            Description = "Inspect a domain's DNS inventory, providers, and common record coverage",
            Category = ToolCategory.Dns,
            Icon = "search",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DNSINVENTORY",
            PowerShellExample = "Test-DomainHealth -DomainName 'example.com' -HealthCheckType DNSINVENTORY",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDnsInventoryAsync(\"example.com\");"
        },
        new ToolDefinition {
            Name = "DNSSEC Check",
            Slug = "dnssec",
            Description = "Validate DNSSEC chain of trust",
            Category = ToolCategory.Dns,
            Icon = "shield",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DNSSEC",
            PowerShellExample = "Test-DDDnsSecStatus -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDNSSEC(\"example.com\");"
        },
        new ToolDefinition {
            Name = "SOA Lookup",
            Slug = "soa",
            Description = "Check SOA record and zone authority",
            Category = ToolCategory.Dns,
            Icon = "server",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks SOA",
            PowerShellExample = "Test-DDDnsSoaRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifySOA(\"example.com\");"
        },
        new ToolDefinition {
            Name = "NS Lookup",
            Slug = "ns",
            Description = "List authoritative nameservers",
            Category = ToolCategory.Dns,
            Icon = "globe",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks NS",
            PowerShellExample = "Test-DDDnsNsRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyNS(\"example.com\");"
        },
        new ToolDefinition {
            Name = "DNS Propagation",
            Slug = "dns-propagation",
            Description = "Compare DNS answers across DomainDetective's distributed public resolver pool",
            Category = ToolCategory.Dns,
            Icon = "radio",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            LiteCompatible = true,
            CliExample = "domaindetective DnsPropagation --domain 'example.com' --record-type A",
            PowerShellExample = "Test-DDDnsPropagation -DomainName 'example.com' -RecordType A",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDnsPropagationAsync(\"example.com\");"
        },

        // TLS & Certificates
        new ToolDefinition {
            Name = "Certificate Check",
            Slug = "cert-check",
            Description = "Inspect TLS certificate details and chain",
            Category = ToolCategory.TlsCert,
            Icon = "award",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            CliExample = "domaindetective check 'example.com' --checks CERT",
            PowerShellExample = "Test-DDDomainCertificate -Url 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyWebsiteCertificate(\"example.com\");"
        },
        new ToolDefinition {
            Name = "CAA Lookup",
            Slug = "caa",
            Description = "Check Certificate Authority Authorization records",
            Category = ToolCategory.TlsCert,
            Icon = "check-square",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks CAA",
            PowerShellExample = "Test-DDDnsCaaRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyCAA(\"example.com\");"
        },
        new ToolDefinition {
            Name = "DANE Check",
            Slug = "dane",
            Description = "Validate DANE/TLSA records",
            Category = ToolCategory.TlsCert,
            Icon = "link",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DANE",
            PowerShellExample = "Test-DDTlsDaneRecord -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDANE(\"example.com\", new[] { 443 });"
        },

        // Web Security
        new ToolDefinition {
            Name = "HTTP Headers",
            Slug = "http-headers",
            Description = "Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)",
            Category = ToolCategory.WebSecurity,
            Icon = "code",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            CliExample = "domaindetective check 'example.com' --checks WEBSITE",
            PowerShellExample = "Test-DDWebsiteSecurity -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyWebsiteHttps(\"example.com\");"
        },
        new ToolDefinition {
            Name = "Security.txt",
            Slug = "security-txt",
            Description = "Check for security.txt disclosure file",
            Category = ToolCategory.WebSecurity,
            Icon = "file-text",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            CliExample = "domaindetective check 'example.com' --checks SECURITYTXT",
            PowerShellExample = "Test-DDDomainSecurityTxt -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifySecurityTxt(\"example.com\");"
        },

        // Registration
        new ToolDefinition {
            Name = "RDAP / WHOIS",
            Slug = "rdap",
            Description = "Query domain registration data via RDAP",
            Category = ToolCategory.Registration,
            Icon = "database",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            CliExample = "domaindetective TestRDAP 'example.com'",
            PowerShellExample = "Get-DDRdap -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.QueryRDAP(\"example.com\");"
        },

        // Threat Intel
        new ToolDefinition {
            Name = "DNSBL Check",
            Slug = "dnsbl",
            Description = "Check domain/IP against DNS blacklists",
            Category = ToolCategory.ThreatIntel,
            Icon = "alert-triangle",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DNSBL",
            PowerShellExample = "Test-DDDnsBlacklist -NameOrIpAddress 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDNSBL(\"example.com\");"
        },
        new ToolDefinition {
            Name = "Dangling CNAME",
            Slug = "dangling-cname",
            Description = "Detect dangling CNAME records vulnerable to takeover",
            Category = ToolCategory.ThreatIntel,
            Icon = "alert-circle",
            InputPlaceholder = "example.com",
            CliExample = "domaindetective check 'example.com' --checks DANGLINGCNAME",
            PowerShellExample = "Test-DDDnsDanglingCname -DomainName 'example.com'",
            CSharpExample = "var hc = new DomainHealthCheck();\nawait hc.VerifyDanglingCname(\"example.com\");"
        },

        // Subdomain
        new ToolDefinition {
            Name = "CT Subdomain Discovery",
            Slug = "ct-subdomains",
            Description = "Discover subdomains via Certificate Transparency logs",
            Category = ToolCategory.Subdomain,
            Icon = "layers",
            InputPlaceholder = "example.com",
            BrowserCompatible = false,
            HostedCompatible = true,
            CliExample = "domaindetective cert-inventory-capture 'example.com' --include-ct-subdomains",
            PowerShellExample = "Invoke-DDCertificateInventory -DomainName 'example.com' -IncludeCtSubdomains",
            CSharpExample = "var capture = new CertificateInventoryCapture();\nvar options = new CertificateInventoryCaptureOptions { IncludeCtDiscoveredSubdomains = true };\nawait capture.CaptureAsync(new[] { \"example.com\" }, options);"
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
        ToolCategory.Overview => "Overview",
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
        ToolCategory.Overview => "layout-dashboard",
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
