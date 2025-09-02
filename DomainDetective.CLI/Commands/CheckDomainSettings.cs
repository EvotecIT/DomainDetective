using Spectre.Console.Cli;
using System.IO;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="CheckDomainCommand"/>.
/// </summary>
internal sealed class CheckDomainSettings : CommandSettings {
    /// <summary>Domains to analyze.</summary>
    [CommandArgument(0, "[domains]")]
    public string[] Domains { get; set; } = Array.Empty<string>();

    /// <summary>Comma separated list of checks.</summary>
    [CommandOption("--checks")]
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
    [CommandOption("--dane-ports")]
    public string? DanePorts { get; set; }

    /// <summary>Comma separated list of port scan profiles.</summary>
    [CommandOption("--port-profiles")]
    public string? PortProfiles { get; set; }

    /// <summary>Path to S/MIME certificate.</summary>
    [CommandOption("--smime")]
    public FileInfo? Smime { get; set; }

    /// <summary>Path to certificate to analyze.</summary>
    [CommandOption("--cert")]
    public FileInfo? Cert { get; set; }

    /// <summary>Suppress progress output.</summary>
    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }

    /// <summary>Skip certificate revocation checks.</summary>
    [CommandOption("--skip-revocation")]
    public bool SkipRevocation { get; set; }

    // Static web scan options
    /// <summary>Run a static (no-browser) web scan for a specific URL.</summary>
    [CommandOption("--webscan-static")]
    public string? WebScanStatic { get; set; }
    /// <summary>Alias for --webscan-static.</summary>
    [CommandOption("--webscan")]
    public string? WebScan { get; set; }

    /// <summary>Time budget for web scan in seconds (default 30).</summary>
    [CommandOption("--webscan-max-seconds")]
    public int WebScanMaxSeconds { get; set; } = 30;

    /// <summary>Maximum number of resources to fetch (default 300).</summary>
    [CommandOption("--webscan-max-resources")]
    public int WebScanMaxResources { get; set; } = 300;

    /// <summary>Optional path to tech-detection rules JSON file.</summary>
    [CommandOption("--techrules")]
    public string? TechRules { get; set; }

    // Concurrency tuning for static web scan
    /// <summary>Max parallel discovery (HEAD/GET) requests; 0 defers to default.</summary>
    [CommandOption("--webscan-discovery-threads")]
    public int WebScanDiscoveryThreads { get; set; } = 0;

    /// <summary>Max parallel CSS fetch/parse threads; 0 defers to default.</summary>
    [CommandOption("--webscan-css-threads")]
    public int WebScanCssThreads { get; set; } = 0;

    /// <summary>Max parallel TLS probes; 0 defers to default.</summary>
    [CommandOption("--webscan-tls-threads")]
    public int WebScanTlsThreads { get; set; } = 0;

    /// <summary>Max parallel DNS/RDAP enrichments; 0 defers to default.</summary>
    [CommandOption("--webscan-dns-threads")]
    public int WebScanDnsThreads { get; set; } = 0;

    /// <summary>Respect robots.txt Disallow/Allow rules during discovery.</summary>
    [CommandOption("--webscan-respect-robots")]
    public bool WebScanRespectRobots { get; set; }

    /// <summary>Skip third-party resources (first-party only crawl).</summary>
    [CommandOption("--webscan-first-party-only")]
    public bool WebScanFirstPartyOnly { get; set; }
}
