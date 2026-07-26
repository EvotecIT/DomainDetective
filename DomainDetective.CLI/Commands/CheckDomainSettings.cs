using Spectre.Console.Cli;
using System.IO;
using DnsClientX;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="CheckDomainCommand"/>.
/// </summary>
internal sealed class CheckDomainSettings : CommandSettings {
    /// <summary>Domains to analyze.</summary>
    [CommandArgument(0, "<domains>")]
    public string[] Domains { get; set; } = Array.Empty<string>();

    /// <summary>Comma separated list of checks.</summary>
    [CommandOption("--checks <CHECKS>")]
    public string[] Checks { get; set; } = Array.Empty<string>();

    /// <summary>Perform plain HTTP check.</summary>
    [CommandOption("--check-http")]
    public bool CheckHttp { get; set; }

    /// <summary>Perform HTTPS web checks (cert + headers/mixed-content).</summary>
    [CommandOption("--check-web")]
    public bool CheckWeb { get; set; }

    /// <summary>Check for takeover vulnerable CNAMEs.</summary>
    [CommandOption("--check-takeover")]
    public bool CheckTakeover { get; set; }

    /// <summary>Output Autodiscover HTTP endpoints.</summary>
    [CommandOption("--autodiscover-endpoints")]
    public bool AutodiscoverEndpoints { get; set; }

    /// <summary>Show condensed summary instead of full results.</summary>
    [CommandOption("--summary")]
    public bool Summary { get; set; }

    /// <summary>Output JSON to the console.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }

    /// <summary>Show output using Unicode characters.</summary>
    [CommandOption("--unicode")]
    public bool Unicode { get; set; }

    /// <summary>Evaluate subdomain policy on DMARC record.</summary>
    [CommandOption("--subdomain-policy")]
    public bool SubdomainPolicy { get; set; }

    /// <summary>Comma separated list of ports for DANE checks.</summary>
    [CommandOption("--dane-ports <PORTS>")]
    public string? DanePorts { get; set; }

    /// <summary>Comma separated list of port scan profiles.</summary>
    [CommandOption("--port-profiles <PROFILES>")]
    public string? PortProfiles { get; set; }

    /// <summary>Path to S/MIME certificate.</summary>
    [CommandOption("--smime <PATH>")]
    public FileInfo? Smime { get; set; }

    /// <summary>Path to certificate to analyze.</summary>
    [CommandOption("--cert <PATH>")]
    public FileInfo? Cert { get; set; }

    /// <summary>Suppress progress output.</summary>
    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }

    /// <summary>Skip certificate revocation checks.</summary>
    [CommandOption("--skip-revocation")]
    public bool SkipRevocation { get; set; }

    // Static web scan options
    /// <summary>Run a static (no-browser) web scan for a specific URL.</summary>
    [CommandOption("--webscan-static <URL>")]
    public string? WebScanStatic { get; set; }
    /// <summary>Alias for --webscan-static.</summary>
    [CommandOption("--webscan <URL>")]
    public string? WebScan { get; set; }

    /// <summary>Time budget for web scan in seconds (default 30).</summary>
    [CommandOption("--webscan-max-seconds <SECONDS>")]
    public int WebScanMaxSeconds { get; set; } = 30;

    /// <summary>Maximum number of resources to fetch (default 300).</summary>
    [CommandOption("--webscan-max-resources <N>")]
    public int WebScanMaxResources { get; set; } = 300;

    /// <summary>Optional path to tech-detection rules JSON file.</summary>
    [CommandOption("--techrules <PATH>")]
    public string? TechRules { get; set; }

    // Concurrency tuning for static web scan
    /// <summary>Max parallel discovery (HEAD/GET) requests; 0 defers to default.</summary>
    [CommandOption("--webscan-discovery-threads <N>")]
    public int WebScanDiscoveryThreads { get; set; } = 0;

    /// <summary>Max parallel CSS fetch/parse threads; 0 defers to default.</summary>
    [CommandOption("--webscan-css-threads <N>")]
    public int WebScanCssThreads { get; set; } = 0;

    /// <summary>Max parallel TLS probes; 0 defers to default.</summary>
    [CommandOption("--webscan-tls-threads <N>")]
    public int WebScanTlsThreads { get; set; } = 0;

    /// <summary>Max parallel DNS/RDAP enrichments; 0 defers to default.</summary>
    [CommandOption("--webscan-dns-threads <N>")]
    public int WebScanDnsThreads { get; set; } = 0;

    /// <summary>Respect robots.txt Disallow/Allow rules during discovery.</summary>
    [CommandOption("--webscan-respect-robots")]
    public bool WebScanRespectRobots { get; set; }

    /// <summary>Skip third-party resources (first-party only crawl).</summary>
    [CommandOption("--webscan-first-party-only")]
    public bool WebScanFirstPartyOnly { get; set; }

    // Link check controls for web scan
    /// <summary>Follow anchor links and check them (bounded).</summary>
    [CommandOption("--webscan-follow-links")]
    public bool WebScanFollowLinks { get; set; }

    /// <summary>Maximum link depth to follow.</summary>
    [CommandOption("--webscan-link-max-depth <N>")]
    public int WebScanLinkMaxDepth { get; set; } = 0;

    /// <summary>Maximum number of link pages to check.</summary>
    [CommandOption("--webscan-link-max-pages <N>")]
    public int WebScanLinkMaxPages { get; set; } = 100;

    /// <summary>Restrict link checking to first-party only.</summary>
    [CommandOption("--webscan-link-first-party-only")]
    public bool WebScanLinkFirstPartyOnly { get; set; }

    /// <summary>Parallel threads for link checks; 0 defers to discovery threads.</summary>
    [CommandOption("--webscan-link-threads <N>")]
    public int WebScanLinkThreads { get; set; } = 0;

    /// <summary>Link-only mode: skip static resource discovery and only check links.</summary>
    [CommandOption("--webscan-link-only")]
    public bool WebScanLinkOnly { get; set; }

    /// <summary>Primary DNS endpoint used for resolver queries.</summary>
    [CommandOption("--dns-endpoint <ENDPOINT>")]
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

    /// <summary>Optional list of DNS endpoints to use (multi-resolver). Use multiple flags or comma-separated values.</summary>
    [CommandOption("--dns-endpoints <ENDPOINTS>")]
    public string[] DnsEndpoints { get; set; } = Array.Empty<string>();

    /// <summary>Strategy used when multiple DNS endpoints are provided.</summary>
    [CommandOption("--dns-strategy <STRATEGY>")]
    public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

    /// <summary>Maximum number of resolvers to query in parallel (null = all).</summary>
    [CommandOption("--dns-endpoints-parallelism <N>")]
    public int? MultiResolverMaxParallelism { get; set; }

    /// <summary>Maximum number of subdomains to verify for DNS resolution (null = default).</summary>
    [CommandOption("--subdomains-max-resolution-checks <N>")]
    public int? SubdomainsMaxResolutionChecks { get; set; }

    /// <summary>Maximum number of concurrent DNS checks for subdomain resolution verification (null = default).</summary>
    [CommandOption("--subdomains-resolution-concurrency <N>")]
    public int? SubdomainsResolutionConcurrency { get; set; }

    /// <summary>Minimum interval between DNS queries during subdomain resolution verification, in milliseconds (null = default).</summary>
    [CommandOption("--subdomains-resolution-min-interval-ms <MS>")]
    public int? SubdomainsResolutionMinIntervalMs { get; set; }
}
