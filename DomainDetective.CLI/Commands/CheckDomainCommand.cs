using DomainDetective;
using DnsClientX;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
using Spectre.Console;
using Spectre.Console.Cli;
using System.IO;
using System.Linq;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using DomainDetective.Helpers;

namespace DomainDetective.CLI;

/// <summary>
/// Performs health checks against specified domains.
/// </summary>
internal sealed class CheckDomainCommand : AsyncCommand<CheckDomainSettings> {
    /// <inheritdoc/>
    protected override async Task<int> ExecuteAsync(CommandContext context, CheckDomainSettings settings, CancellationToken cancellationToken) {
        var dnsEndpoint = settings.DnsEndpoint;
        var dnsEndpoints = CommandUtilities.ParseDnsEndpoints(settings.DnsEndpoints, out var invalidDnsEndpoints);
        if (invalidDnsEndpoints.Count > 0)
        {
            var joined = string.Join(", ", invalidDnsEndpoints.Distinct(StringComparer.OrdinalIgnoreCase));
            AnsiConsole.MarkupLine($"[yellow]Ignoring invalid --dns-endpoints value(s):[/] {joined}");
        }

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
            await certAnalysis.AnalyzeCertificate(CertificateLoaderCompat.LoadCertificateFromFile(settings.Cert.FullName));
            CliHelpers.ShowPropertiesTable($"Certificate {settings.Cert.FullName}", certAnalysis, settings.Unicode);
            return 0;
        }

        // Single-URL static web scan mode
        var webScanTarget = !string.IsNullOrWhiteSpace(settings.WebScanStatic) ? settings.WebScanStatic : settings.WebScan;
        if (!string.IsNullOrWhiteSpace(webScanTarget)) {
            var raw = webScanTarget!.Trim();
            var hc = new DomainHealthCheck(dnsEndpoint) {
                Progress = false,
                Verbose = false
            };
            if (dnsEndpoints != null && dnsEndpoints.Length > 0)
            {
                hc.DnsEndpoints.Clear();
                hc.DnsEndpoints.AddRange(dnsEndpoints);
                hc.MultiResolverStrategy = settings.MultiResolverStrategy;
                hc.MultiResolverMaxParallelism = settings.MultiResolverMaxParallelism;
            }
            hc.WebStaticScanAnalysis.Timeout = TimeSpan.FromSeconds(Math.Max(1, settings.WebScanMaxSeconds));
            hc.WebStaticScanAnalysis.MaxResources = Math.Max(1, settings.WebScanMaxResources);
            hc.WebStaticScanAnalysis.DiscoveryConcurrency = Math.Max(0, settings.WebScanDiscoveryThreads);
            hc.WebStaticScanAnalysis.CssConcurrency = Math.Max(0, settings.WebScanCssThreads);
            hc.WebStaticScanAnalysis.TlsConcurrency = Math.Max(0, settings.WebScanTlsThreads);
            hc.WebStaticScanAnalysis.DnsConcurrency = Math.Max(0, settings.WebScanDnsThreads);
            hc.WebStaticScanAnalysis.RespectRobots = settings.WebScanRespectRobots;
            hc.WebStaticScanAnalysis.SkipThirdParty = settings.WebScanFirstPartyOnly;
            // Link controls
            hc.WebStaticScanAnalysis.FollowLinks = settings.WebScanFollowLinks;
            hc.WebStaticScanAnalysis.LinkMaxDepth = Math.Max(0, settings.WebScanLinkMaxDepth);
            hc.WebStaticScanAnalysis.LinkMaxPages = Math.Max(1, settings.WebScanLinkMaxPages);
            hc.WebStaticScanAnalysis.LinkFirstPartyOnly = settings.WebScanLinkFirstPartyOnly || hc.WebStaticScanAnalysis.LinkFirstPartyOnly;
            hc.WebStaticScanAnalysis.LinkConcurrency = Math.Max(0, settings.WebScanLinkThreads);
            hc.WebStaticScanAnalysis.LinkOnly = settings.WebScanLinkOnly;
            if (!string.IsNullOrWhiteSpace(settings.TechRules)) hc.WebStaticScanAnalysis.TechRulesPath = settings.TechRules;
            // Normalize input: allow bare domain; prefer http first to observe redirects, then fallback to https
            bool hasScheme = false;
            try { var u = new Uri(raw); hasScheme = u.Scheme == "http" || u.Scheme == "https"; } catch { }
            string startUrl = raw;
            if (!hasScheme) {
                var httpUrl = $"http://{raw}";
                var httpsUrl = $"https://{raw}";
                try {
                    await hc.VerifyWebStaticScan(httpUrl, cancellationToken);
                    startUrl = httpUrl;
                } catch {
                    await hc.VerifyWebStaticScan(httpsUrl, cancellationToken);
                    startUrl = httpsUrl;
                }
            } else {
                await hc.VerifyWebStaticScan(startUrl, cancellationToken);
            }
            var view = DomainDetective.Views.Converters.Convert(hc.WebStaticScanAnalysis);
            CliHelpers.ShowPropertiesTable($"WEB STATIC for {startUrl}", view, settings.Unicode);
            return 0;
        }

        if (settings.Domains.Length == 0) {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.InputEncoding = System.Text.Encoding.UTF8;
            return await WizardMode.RunInteractiveWizard(cancellationToken);
        }

        settings.Domains = settings.Domains
            .Select(CliHelpers.ToAscii)
            .ToArray();

        var selected = CommandUtilities.ParseDomainChecks(settings.Checks, out var invalidChecks, out var unsupportedChecks);
        if (invalidChecks.Count > 0)
        {
            var joined = string.Join(", ", invalidChecks);
            AnsiConsole.MarkupLine($"[yellow]Ignoring invalid --checks value(s):[/] {joined}");
        }
        if (unsupportedChecks.Count > 0)
        {
            var joined = string.Join(", ", unsupportedChecks);
            throw new InvalidOperationException(
                $"The following checks require specialized input and cannot be used with 'check': {joined}.");
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
            selected.Length > 0 ? selected : null,
            settings.CheckHttp,
            settings.CheckWeb,
            settings.CheckTakeover,
            settings.AutodiscoverEndpoints,
            settings.Json,
            settings.Summary,
            settings.SubdomainPolicy,
            settings.Unicode,
            danePorts,
            !settings.NoProgress,
            settings.SkipRevocation,
            scanProfiles,
            dnsEndpoint: dnsEndpoint,
            dnsEndpoints: dnsEndpoints,
            multiResolverStrategy: settings.MultiResolverStrategy,
            multiResolverMaxParallelism: settings.MultiResolverMaxParallelism,
            subdomainsMaxResolutionChecks: settings.SubdomainsMaxResolutionChecks,
            subdomainsResolutionConcurrency: settings.SubdomainsResolutionConcurrency,
            subdomainsResolutionMinIntervalMs: settings.SubdomainsResolutionMinIntervalMs,
            cancellationToken: cancellationToken);

        return 0;
    }
}
