using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using DnsClientX;
using Spectre.Console;
using Spectre.Console.Cli;
using DomainDetective.DesiredState;
using DomainDetective.Helpers;
using DomainDetective.Reports;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Evaluates a domain against a Desired State baseline.
/// </summary>
internal sealed class DesiredStateCommand : AsyncCommand<DesiredStateCommand.Settings> {
    public sealed class Settings : CommandSettings {
        [Description("Domain(s) to evaluate")]
        [CommandArgument(0, "<domains>")]
        public string[] Domains { get; set; } = Array.Empty<string>();

        [Description("Desired state configuration JSON path")]
        [CommandOption("--desired-state|--config <PATH>")]
        public string? DesiredStatePath { get; set; }

        [Description("Override desired state mode (BaselineOnly | HybridSplit | BestPracticesForUnspecified)")]
        [CommandOption("--mode <MODE>")]
        public string? Mode { get; set; }

        [Description("Skip mail classification even if overrides request it")]
        [CommandOption("--no-classification")]
        public bool NoClassification { get; set; }

        [Description("Fail fast when evaluation throws")]
        [CommandOption("--fail-fast")]
        public bool FailFast { get; set; }

        [Description("Log evaluation exceptions as errors instead of warnings")]
        [CommandOption("--log-eval-errors")]
        public bool LogEvaluationErrorsAsErrors { get; set; }

        [Description("Output JSON to the console")]
        [CommandOption("--json")]
        public bool Json { get; set; }

        [Description("Show output using Unicode characters")]
        [CommandOption("--unicode")]
        public bool Unicode { get; set; }

        [Description("Export report format(s): html, word, excel, markdown, markdownhtml, json")]
        [CommandOption("-f|--format|--report <FORMAT>")]
        public string[] Formats { get; set; } = Array.Empty<string>();

        [Description("Output file path (optional; defaults to auto-generated name)")]
        [CommandOption("-o|--output <PATH>")]
        public string? OutputPath { get; set; }

        [Description("Open generated HTML report in browser")]
        [CommandOption("--open")]
        public bool OpenInBrowser { get; set; }

        [Description("Primary DNS endpoint used for resolver queries")]
        [CommandOption("--dns-endpoint <ENDPOINT>")]
        [DefaultValue(DnsEndpoint.System)]
        public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

        [Description("Optional list of DNS endpoints to use (multi-resolver). Use multiple flags or comma-separated values.")]
        [CommandOption("--dns-endpoints <ENDPOINTS>")]
        public string[] DnsEndpoints { get; set; } = Array.Empty<string>();

        [Description("Strategy used when multiple DNS endpoints are provided")]
        [CommandOption("--dns-strategy <STRATEGY>")]
        [DefaultValue(MultiResolverStrategy.FirstSuccess)]
        public MultiResolverStrategy MultiResolverStrategy { get; set; } = MultiResolverStrategy.FirstSuccess;

        [Description("Maximum number of resolvers to query in parallel (null = all)")]
        [CommandOption("--dns-endpoints-parallelism <N>")]
        public int? MultiResolverMaxParallelism { get; set; }
    }

    protected override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken) {
        var config = LoadConfiguration(settings.DesiredStatePath);
        var mode = ResolveMode(settings.Mode, config.Mode);
        var wantsClassification = !settings.NoClassification && config.RequiresMailClassification();

        var domains = settings.Domains.Length > 0
            ? settings.Domains.Select(CliHelpers.ToAscii).ToArray()
            : Array.Empty<string>();

        if (domains.Length == 0) {
            AnsiConsole.MarkupLine("[red]No domains specified.[/]");
            return 1;
        }

        var exportFormats = ParseFormats(settings.Formats);
        var exportRequested = exportFormats.Count > 0 || !string.IsNullOrWhiteSpace(settings.OutputPath);

        var views = new List<DomainDetective.Views.DesiredStateInfo>();
        var successfulDomains = 0;
        var failedDomains = 0;

        foreach (var domain in domains) {
            try {
                var logger = new InternalLogger(false);
                var healthCheck = new DomainHealthCheck(settings.DnsEndpoint, logger);

                var dnsEndpoints = CommandUtilities.ParseDnsEndpoints(settings.DnsEndpoints, out var invalidDnsEndpoints);
                if (invalidDnsEndpoints.Count > 0) {
                    var joined = string.Join(", ", invalidDnsEndpoints.Distinct(StringComparer.OrdinalIgnoreCase));
                    AnsiConsole.MarkupLine($"[yellow]Ignoring invalid --dns-endpoints value(s):[/] {joined}");
                }
                if (dnsEndpoints != null && dnsEndpoints.Length > 0) {
                    healthCheck.DnsEndpoints.Clear();
                    healthCheck.DnsEndpoints.AddRange(dnsEndpoints);
                    healthCheck.MultiResolverStrategy = settings.MultiResolverStrategy;
                    healthCheck.MultiResolverMaxParallelism = settings.MultiResolverMaxParallelism;
                }

                DomainDetective.Definitions.MailDomainClassificationCategory? classification = null;
                if (wantsClassification) {
                    var classifier = new MailDomainClassifier(healthCheck, logger);
                    var mc = await classifier.ClassifyAsync(domain, cancellationToken);
                    classification = mc.Classification;
                }

                var profile = config.ResolveProfile(domain, classification);
                var toRun = config.GetChecksToRun(profile, mode);

                string[]? dkimSelectors = null;
                if (profile.Dkim != null && profile.Dkim.Enabled != false && profile.Dkim.RequiredSelectors != null && profile.Dkim.RequiredSelectors.Length > 0) {
                    dkimSelectors = profile.Dkim.RequiredSelectors;
                    healthCheck.ExecutionOptions.IncludeMissingDkimSelectors = true;
                }

                ServiceType[]? daneServiceTypes = null;
                if (profile.Dane != null && profile.Dane.Enabled != false && profile.Dane.RequiredServices != null && profile.Dane.RequiredServices.Length > 0) {
                    daneServiceTypes = profile.Dane.RequiredServices;
                }

                if (profile.Bimi != null && profile.Bimi.Enabled != false && profile.Bimi.SkipIndicatorDownload == true) {
                    healthCheck.ExecutionOptions.SkipBimiIndicatorDownload = true;
                }

                await healthCheck.Verify(
                    domain,
                    healthCheckTypes: toRun,
                    dkimSelectors: dkimSelectors,
                    daneServiceType: daneServiceTypes,
                    cancellationToken: cancellationToken,
                    useDefaultChecksWhenEmpty: false);

                var desired = DesiredStateEvaluator.Evaluate(domain, healthCheck, profile, classification, new DesiredStateEvaluationOptions {
                    ThrowOnError = settings.FailFast,
                    LogExceptionsAsErrors = settings.LogEvaluationErrorsAsErrors
                });
                desired.Mode = mode;
                var view = DomainDetective.Views.Converters.Convert(desired, profile, mode);
                views.Add(view);
                successfulDomains++;

                if (!exportRequested && !settings.Json) {
                    CliHelpers.ShowPropertiesTable($"Desired State for {domain}", view, settings.Unicode);
                }
            } catch (OperationCanceledException) {
                throw;
            } catch (Exception ex) {
                failedDomains++;
                AnsiConsole.MarkupLine($"[red]Desired state evaluation failed for {domain}: {ex.Message}[/]");
            }
        }

        if (successfulDomains == 0) {
            if (failedDomains > 0) {
                AnsiConsole.MarkupLine("[red]Desired state evaluation failed for all requested domains.[/]");
            }
            return 1;
        }

        if (settings.Json) {
            object payload = views.Count == 1 ? views[0] : views;
            Console.WriteLine(JsonSerializer.Serialize(payload, JsonOptions.Default));
        }

        if (exportRequested && views.Count > 0) {
            var request = new CompositionExportRequest {
                Items = views,
                Formats = exportFormats.Count > 0 ? exportFormats : new[] { ReportFormat.Html },
                ExportPath = settings.OutputPath,
                OpenInBrowser = settings.OpenInBrowser
            };
            var result = await CompositionExportService.ExportAsync(request, null, cancellationToken).ConfigureAwait(false);
            var failed = result.Reports.Where(r => !r.Success).ToList();
            if (failed.Count > 0) {
                foreach (var r in failed) {
                    AnsiConsole.MarkupLine($"[yellow]Export failed for {r.Format}: {r.ErrorMessage}[/]");
                }
                return 1;
            }
        }

        return 0;
    }

    private static DesiredStateConfiguration LoadConfiguration(string? path) {
        if (string.IsNullOrWhiteSpace(path)) {
            return new DesiredStateConfiguration();
        }

        var full = Path.GetFullPath(path);
        return DesiredStateConfiguration.Load(full);
    }

    private static DesiredStateMode ResolveMode(string? mode, DesiredStateMode fallback) {
        if (string.IsNullOrWhiteSpace(mode)) {
            return fallback;
        }

        if (Enum.TryParse(mode, true, out DesiredStateMode parsed)) {
            return parsed;
        }

        throw new ArgumentException($"Invalid desired state mode '{mode}'. Expected BaselineOnly, HybridSplit, or BestPracticesForUnspecified.");
    }

    private static List<ReportFormat> ParseFormats(string[] raw) {
        var list = new List<ReportFormat>();
        if (raw == null || raw.Length == 0) {
            return list;
        }

        foreach (var entry in raw) {
            if (string.IsNullOrWhiteSpace(entry)) continue;
            foreach (var token in entry.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) {
                if (TryParseFormat(token, out var fmt)) {
                    list.Add(fmt);
                } else {
                    AnsiConsole.MarkupLine($"[yellow]Unknown format '{token}' ignored.[/]");
                }
            }
        }

        return list.Distinct().ToList();
    }

    private static bool TryParseFormat(string token, out ReportFormat format) {
        format = ReportFormat.Html;
        if (string.IsNullOrWhiteSpace(token)) return false;
        switch (token.Trim().ToLowerInvariant()) {
            case "html":
                format = ReportFormat.Html;
                return true;
            case "word":
            case "docx":
                format = ReportFormat.Word;
                return true;
            case "excel":
            case "xlsx":
                format = ReportFormat.Excel;
                return true;
            case "markdown":
            case "md":
                format = ReportFormat.Markdown;
                return true;
            case "markdownhtml":
            case "mdhtml":
                format = ReportFormat.MarkdownHtml;
                return true;
            case "json":
                format = ReportFormat.Json;
                return true;
            default:
                return false;
        }
    }
}
