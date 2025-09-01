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
}
