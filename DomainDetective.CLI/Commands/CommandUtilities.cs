using DomainDetective;
using DnsClientX;
using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
using Spectre.Console;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using DomainDetective.Helpers;
using System.Text.Json;
using System.Threading;

namespace DomainDetective.CLI;

/// <summary>
/// Helper methods used by CLI commands.
/// </summary>
internal static partial class CommandUtilities {
    internal static readonly string[] CheckNames = Enum.GetNames<HealthCheckType>();
    internal static readonly string[] DomainCheckNames = Enum
        .GetValues<HealthCheckType>()
        .Where(DomainHealthCheck.SupportsDomainVerification)
        .Select(static check => check.ToString())
        .ToArray();
    internal static readonly string[] PortProfileNames = Enum.GetNames<PortScanProfile>();

    internal static HealthCheckType[] ParseDomainChecks(
        IEnumerable<string> rawChecks,
        out IReadOnlyList<string> invalidChecks,
        out IReadOnlyList<HealthCheckType> unsupportedChecks)
    {
        var selected = new List<HealthCheckType>();
        var invalid = new List<string>();

        foreach (var rawCheck in rawChecks ?? Array.Empty<string>())
        {
            if (string.IsNullOrWhiteSpace(rawCheck))
            {
                continue;
            }

            foreach (var token in rawCheck.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Enum.TryParse<HealthCheckType>(token, true, out var type))
                {
                    selected.Add(type);
                }
                else
                {
                    invalid.Add(token);
                }
            }
        }

        invalidChecks = invalid
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        unsupportedChecks = selected
            .Where(type => !DomainHealthCheck.SupportsDomainVerification(type))
            .Distinct()
            .ToArray();

        return selected
            .Where(DomainHealthCheck.SupportsDomainVerification)
            .Distinct()
            .ToArray();
    }

    internal static DnsEndpoint[]? ParseDnsEndpoints(string[]? raw, out List<string> invalid)
    {
        invalid = new List<string>();
        if (raw == null || raw.Length == 0)
        {
            return null;
        }

        var endpoints = new List<DnsEndpoint>();
        foreach (var part in raw)
        {
            if (string.IsNullOrWhiteSpace(part))
            {
                continue;
            }

            foreach (var token in part.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Enum.TryParse<DnsEndpoint>(token, true, out var ep))
                {
                    endpoints.Add(ep);
                }
                else
                {
                    invalid.Add(token);
                }
            }
        }

        return endpoints.Count == 0 ? null : endpoints.Distinct().ToArray();
    }

    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    internal static void AnalyzeARC(FileInfo? file, string? header, bool json) {
        string? headerText = null;
        if (file != null) {
            if (!file.Exists) {
                throw new FileNotFoundException($"File not found: {file.FullName}", file.FullName);
            }
            headerText = File.ReadAllText(file.FullName);
        } else if (!string.IsNullOrWhiteSpace(header)) {
            headerText = header;
        }

        if (string.IsNullOrWhiteSpace(headerText)) {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return;
        }

        var hc = new DomainHealthCheck();
        var result = hc.VerifyARCAsync(headerText).GetAwaiter().GetResult();

        if (json) {
            var jsonText = JsonSerializer.Serialize(result, JsonOptions.Default);
            Console.WriteLine(jsonText);
        } else {
            CliHelpers.ShowPropertiesTable("ARC Analysis", result, false);
        }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    internal static void AnalyzeDnsTunneling(string domain, string filePath, bool json) {
        if (!File.Exists(filePath)) {
            throw new FileNotFoundException($"File not found: {filePath}", filePath);
        }
        var lines = File.ReadAllLines(filePath);
        var hc = new DomainHealthCheck { DnsTunnelingLogs = lines };
        hc.CheckDnsTunnelingAsync(domain).GetAwaiter().GetResult();
        var result = hc.DnsTunnelingAnalysis;
        if (json) {
            var jsonText = JsonSerializer.Serialize(result, JsonOptions.Default);
            Console.WriteLine(jsonText);
        } else {
            CliHelpers.ShowPropertiesTable($"DNS Tunneling for {domain}", result, false);
        }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<T>(T, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<T>(T, JsonSerializerOptions)")]
    internal static void ImportDmarcForensic(string path, bool json) {
        var reports = DmarcForensicParser.ParseZip(path).ToList();
        if (json) {
            var jsonText = JsonSerializer.Serialize(reports, JsonOptions.Default);
            Console.WriteLine(jsonText);
        } else {
            foreach (var report in reports) {
                CliHelpers.ShowPropertiesTable("DMARC Forensic Report", report, false);
            }
        }
    }

    internal static async Task<int> RunWizard(CancellationToken cancellationToken) {
        AnsiConsole.MarkupLine("[green]DomainDetective CLI Wizard[/]");
        var domainInput = AnsiConsole.Prompt(new TextPrompt<string>("Enter domain(s) [comma separated]:")
            .Validate(input => string.IsNullOrWhiteSpace(input)
                ? ValidationResult.Error("[red]Domain is required[/]")
                : ValidationResult.Success()));
        var domains = domainInput.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var checkPrompt = new MultiSelectionPrompt<string>()
            .Title("Select checks to run")
            .NotRequired()
            .InstructionsText("[grey](Press [blue]space[/] to toggle, [green]enter[/] to accept)[/]")
            .AddChoices(DomainCheckNames);

        var selected = AnsiConsole.Prompt(checkPrompt);
        var checks = selected.Count > 0
            ? selected.Select(c => Enum.TryParse<HealthCheckType>(c, true, out var val) ? val : (HealthCheckType?)null)
                .Where(v => v.HasValue)
                .Select(v => v!.Value)
                .ToArray()
            : null;

        var outputJson = AnsiConsole.Confirm("Output JSON?");
        var summaryOnly = !outputJson && AnsiConsole.Confirm("Show condensed summary?");
        var checkHttp = AnsiConsole.Confirm("Perform plain HTTP check?");
        var subPolicy = AnsiConsole.Confirm("Evaluate subdomain policy?");

        var autodiscoverEndpoints = AnsiConsole.Confirm("Show Autodiscover HTTP endpoints?");

        var checkTakeover = AnsiConsole.Confirm("Check for takeover CNAMEs?");
        return await RunChecks(domains, checks, checkHttp, false, checkTakeover, autodiscoverEndpoints, outputJson, summaryOnly, subPolicy, false, null, true, false, null, cancellationToken: cancellationToken);
    }

	internal static async Task<int> RunChecks(string[] domains, HealthCheckType[]? checks, bool checkHttp, bool checkWeb, bool checkTakeover, bool autodiscoverEndpoints, bool outputJson, bool summaryOnly, bool subdomainPolicy, bool unicodeOutput, int[]? danePorts, bool showProgress, bool skipRevocation, PortScanProfile[]? portScanProfiles, DnsEndpoint dnsEndpoint = DnsEndpoint.System, DnsEndpoint[]? dnsEndpoints = null, MultiResolverStrategy multiResolverStrategy = MultiResolverStrategy.FirstSuccess, int? multiResolverMaxParallelism = null, int? subdomainsMaxResolutionChecks = null, int? subdomainsResolutionConcurrency = null, int? subdomainsResolutionMinIntervalMs = null, CancellationToken cancellationToken = default) {
            bool renderProgress = showProgress && !outputJson;
            var activePlan = (checks == null || checks.Length == 0 ? DomainHealthCheck.DefaultChecks : checks)
                .Concat(checkWeb ? new[] { HealthCheckType.WEBSITE } : Array.Empty<HealthCheckType>()).Distinct().ToArray();
            DomainHealthCheck CreateHealthCheck(string domain) {
	            var logger = new InternalLogger { IsProgress = renderProgress };
	            var hc = new DomainHealthCheck(dnsEndpoint, logger) { Verbose = false, UseSubdomainPolicy = subdomainPolicy, UnicodeOutput = unicodeOutput, Progress = renderProgress };
                if (dnsEndpoints != null && dnsEndpoints.Length > 0)
                {
                    hc.DnsEndpoints.Clear();
                    hc.DnsEndpoints.AddRange(dnsEndpoints);
                    hc.MultiResolverStrategy = multiResolverStrategy;
                    hc.MultiResolverMaxParallelism = multiResolverMaxParallelism;
                }
                if (subdomainsMaxResolutionChecks.HasValue)
                {
                    hc.SubdomainsAnalysis.MaxResolutionChecks = Math.Max(0, subdomainsMaxResolutionChecks.Value);
                }
                if (subdomainsResolutionConcurrency.HasValue)
                {
                    hc.SubdomainsAnalysis.ResolutionConcurrency = Math.Max(1, subdomainsResolutionConcurrency.Value);
                }
                if (subdomainsResolutionMinIntervalMs.HasValue)
                {
                    hc.SubdomainsAnalysis.ResolutionMinInterval = TimeSpan.FromMilliseconds(Math.Max(0, subdomainsResolutionMinIntervalMs.Value));
                }
	            hc.CertificateAnalysis.SkipRevocation = skipRevocation;
	
                return hc;
            }
            var runs = await RunDomainBatchAsync(domains, activePlan, danePorts, portScanProfiles,
                CreateHealthCheck, renderProgress, checkHttp, checkTakeover, cancellationToken);
            try {
                return WriteBatchResults(runs, activePlan, checkHttp, checkWeb, checkTakeover, autodiscoverEndpoints, outputJson, summaryOnly, unicodeOutput);
            } finally {
                foreach (var run in runs) { run.HealthCheck?.Dispose(); }
            }
    }
}
