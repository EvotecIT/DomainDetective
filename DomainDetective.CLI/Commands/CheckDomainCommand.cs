using DomainDetective;
using Spectre.Console;
using Spectre.Console.Cli;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;

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

    /// <summary>Path to S/MIME certificate.</summary>
    [CommandOption("--smime")]
    public FileInfo? Smime { get; set; }

    /// <summary>Path to certificate to analyze.</summary>
    [CommandOption("--cert")]
    public FileInfo? Cert { get; set; }

    /// <summary>Suppress progress output.</summary>
    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }
}

/// <summary>
/// Performs health checks against specified domains.
/// </summary>
internal sealed class CheckDomainCommand : AsyncCommand<CheckDomainSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, CheckDomainSettings settings) {
        if (settings.Smime != null) {
            if (!settings.Smime.Exists) {
                throw new FileNotFoundException("S/MIME certificate file not found", settings.Smime.FullName);
            }
            var smimeAnalysis = new SmimeCertificateAnalysis();
            smimeAnalysis.AnalyzeFile(settings.Smime.FullName);
            CliHelpers.ShowPropertiesTable($"S/MIME certificate {settings.Smime.FullName}", smimeAnalysis, settings.Unicode);
            return 0;
        }

        if (settings.Cert != null) {
            if (!settings.Cert.Exists) {
                throw new FileNotFoundException("Certificate file not found", settings.Cert.FullName);
            }
            var certAnalysis = new CertificateAnalysis();
            await certAnalysis.AnalyzeCertificate(new X509Certificate2(settings.Cert.FullName));
            CliHelpers.ShowPropertiesTable($"Certificate {settings.Cert.FullName}", certAnalysis, settings.Unicode);
            return 0;
        }

        if (settings.Domains.Length == 0) {
            await CommandUtilities.RunWizard(Program.CancellationToken);
            return 0;
        }

        settings.Domains = settings.Domains
            .Select(CliHelpers.ToAscii)
            .ToArray();

        var selected = new List<HealthCheckType>();
        foreach (var check in settings.Checks.SelectMany(c => c.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))) {
            if (CommandUtilities.Options.TryGetValue(check.ToLowerInvariant(), out var type)) {
                selected.Add(type);
            }
        }

        int[]? danePorts = null;
        if (!string.IsNullOrWhiteSpace(settings.DanePorts)) {
            danePorts = settings.DanePorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(p => int.TryParse(p, out var val) ? val : 0)
                .Where(p => p > 0)
                .ToArray();
        }

        await CommandUtilities.RunChecks(
            settings.Domains,
            selected.Count > 0 ? selected.ToArray() : null,
            settings.CheckHttp,
            settings.Json,
            settings.Summary,
            settings.SubdomainPolicy,
            settings.Unicode,
            danePorts,
            !settings.NoProgress,
            Program.CancellationToken);

        return 0;
    }
}
