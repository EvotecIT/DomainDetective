using DomainDetective;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
using Spectre.Console;
using Spectre.Console.Cli;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.CLI;

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
            var certAnalysis = new CertificateAnalysis { SkipRevocation = settings.SkipRevocation };
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
            if (Enum.TryParse<HealthCheckType>(check, true, out var type)) {
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

        PortScanProfile[]? scanProfiles = null;
        if (!string.IsNullOrWhiteSpace(settings.PortProfiles)) {
            scanProfiles = settings.PortProfiles.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(p => Enum.TryParse<PortScanProfile>(p, true, out var val) ? val : (PortScanProfile?)null)
                .Where(p => p.HasValue)
                .Select(p => p!.Value)
                .ToArray();
        }

        await CommandUtilities.RunChecks(
            settings.Domains,
            selected.Count > 0 ? selected.ToArray() : null,
            settings.CheckHttp,
            settings.CheckTakeover,
            settings.Json,
            settings.Summary,
            settings.SubdomainPolicy,
            settings.Unicode,
            danePorts,
            !settings.NoProgress,
            settings.SkipRevocation,
            scanProfiles,
            Program.CancellationToken);

        return 0;
    }
}
