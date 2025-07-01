using DomainDetective;
using Spectre.Console;
using Spectre.Console.Cli;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.CLI;

internal sealed class CheckDomainSettings : CommandSettings {
    [CommandArgument(0, "[domains]")]
    public string[] Domains { get; set; } = Array.Empty<string>();

    [CommandOption("--checks")]
    public string[] Checks { get; set; } = Array.Empty<string>();

    [CommandOption("--check-http")]
    public bool CheckHttp { get; set; }

    [CommandOption("--summary")]
    public bool Summary { get; set; }

    [CommandOption("--json")]
    public bool Json { get; set; }

    [CommandOption("--unicode")]
    public bool Unicode { get; set; }

    [CommandOption("--subdomain-policy")]
    public bool SubdomainPolicy { get; set; }

    [CommandOption("--dane-ports")]
    public string? DanePorts { get; set; }

    [CommandOption("--smime")]
    public FileInfo? Smime { get; set; }

    [CommandOption("--cert")]
    public FileInfo? Cert { get; set; }

    [CommandOption("--no-progress")]
    public bool NoProgress { get; set; }
}

internal sealed class CheckDomainCommand : AsyncCommand<CheckDomainSettings> {
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
            await CommandUtilities.RunWizard();
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
            !settings.NoProgress);

        return 0;
    }
}
