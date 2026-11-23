using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Cli;
using DomainDetective.Reports;
using DomainDetective.Reports.Artifacts;
using DomainDetective.TimeSeries.DmarcAggregate;
using DomainDetective.TimeSeries.Registration;
using DomainDetective.TimeSeries.TlsRpt;
using DnsClientX;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// CLI command for generating domain security reports
/// </summary>
internal sealed class GenerateReportCommand : AsyncCommand<GenerateReportCommand.Settings> {
    public sealed class Settings : CommandSettings {
        [Description("Domain to analyze")]
        [CommandArgument(0, "<domain>")]
        public string Domain { get; set; } = string.Empty;
        
        [Description("Report formats: html, json, word, pdf, excel, markdown, markdownhtml. Repeat the flag or separate formats with commas.")]
        [CommandOption("-f|--format|--report <FORMAT>")]
        public string[] Formats { get; set; } = Array.Empty<string>();
        
        [Description("Output file path")]
        [CommandOption("-o|--output <PATH>")]
        public string? OutputPath { get; set; }
        
        [Description("Assessment template. Only default is supported; document and executive are retired.")]
        [CommandOption("-t|--template <TEMPLATE>")]
        [DefaultValue("default")]
        public string Template { get; set; } = "default";
        
        [Description("HTML theme (system, light, dark). Include HTML to use light or dark in a combined export.")]
        [CommandOption("--theme <THEME>")]
        [DefaultValue("system")]
        public string Theme { get; set; } = "system";
        
        [Description("Open generated reports in their associated application")]
        [CommandOption("--open")]
        [DefaultValue(true)]
        public bool OpenInBrowser { get; set; } = true;
        
        [Description("Assessment reports include technical details; false is unsupported.")]
        [CommandOption("--technical")]
        [DefaultValue(true)]
        public bool IncludeTechnical { get; set; } = true;
        
        [Description("Assessment reports include recommendations; false is unsupported.")]
        [CommandOption("--recommendations")]
        [DefaultValue(true)]
        public bool IncludeRecommendations { get; set; } = true;

        [Description("Optional time-series store root path (adds DMARC Aggregate / TLS-RPT Reports / Registration drift sections when available)")]
        [CommandOption("--store|--store-path <PATH>")]
        public string? StorePath { get; set; }

        [Description("Include authoritative DNS trace section (can be slow)")]
        [CommandOption("--dns-trace")]
        [DefaultValue(false)]
        public bool IncludeDnsTrace { get; set; }

        [Description("Include DNS propagation section (multi-resolver global visibility; can be slow)")]
        [CommandOption("--dns-propagation|--dns-prop")]
        [DefaultValue(false)]
        public bool IncludeDnsPropagation { get; set; }

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
    
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings, CancellationToken cancellationToken) {
        try {
            var formats = ValidatePresentation(settings);

            // Show progress
            await AnsiConsole.Progress()
                .AutoClear(false)
                .Columns(new ProgressColumn[] {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new SpinnerColumn(),
                })
                .StartAsync(async ctx => {
                    // Step 1: Analyze domain
                    var analyzeTask = ctx.AddTask($"[green]Analyzing {settings.Domain}[/]");
                    var logger = new InternalLogger(false);
                    var healthCheck = new DomainHealthCheck(settings.DnsEndpoint, logger);

                    var dnsEndpoints = CommandUtilities.ParseDnsEndpoints(settings.DnsEndpoints, out var invalidDnsEndpoints);
                    if (invalidDnsEndpoints.Count > 0)
                    {
                        var joined = string.Join(", ", invalidDnsEndpoints.Distinct(StringComparer.OrdinalIgnoreCase));
                        AnsiConsole.MarkupLine($"[yellow]Ignoring invalid --dns-endpoints value(s):[/] {joined}");
                    }

                    if (dnsEndpoints != null && dnsEndpoints.Length > 0)
                    {
                        healthCheck.DnsEndpoints.Clear();
                        healthCheck.DnsEndpoints.AddRange(dnsEndpoints);
                        healthCheck.MultiResolverStrategy = settings.MultiResolverStrategy;
                        healthCheck.MultiResolverMaxParallelism = settings.MultiResolverMaxParallelism;
                    }
                    var artifactsBase = DomainDetective.Reports.FilePathHelper.ResolveBaseDirectory(settings.OutputPath, null);
                    using var coord = RunCoordinator.Begin(settings.Domain, logger, artifactsBase);

                    // Report-oriented default check set (broader than DomainHealthCheck.Verify defaults).
	                    var reportChecks = new List<HealthCheckType> {
	                        HealthCheckType.MX,
	                        HealthCheckType.SPF,
	                        HealthCheckType.DKIM,
	                        HealthCheckType.DMARC,
	                        HealthCheckType.TYPOSQUATTING,
	                        HealthCheckType.CAA,
	                        HealthCheckType.DNSBL,
	                        HealthCheckType.RPKI,
	                        HealthCheckType.NS,
	                        HealthCheckType.SOA,
	                        HealthCheckType.TTL,
	                        HealthCheckType.ZONETRANSFER,
	                        HealthCheckType.WILDCARDDNS,
	                        HealthCheckType.MTASTS,
	                        HealthCheckType.TLSRPT,
	                        HealthCheckType.DANE,
	                        HealthCheckType.DNSSEC,
	                        HealthCheckType.HTTP,
	                        HealthCheckType.CTTIMELINE,
	                        HealthCheckType.SUBDOMAINS,
	                        HealthCheckType.DNSINVENTORY,
	                        HealthCheckType.DNSAMPLIFICATION,
	                        HealthCheckType.DNSOVERTLS,
	                        HealthCheckType.IPENRICHMENT,
	                        // Registration and reputation evidence for the risk profile.
	                        HealthCheckType.RDAP,
	                        HealthCheckType.THREATINTEL,
	                        HealthCheckType.FCRDNS,
	                    };
                    if (settings.IncludeDnsTrace) {
                        reportChecks.Add(HealthCheckType.DNSTRACE);
                    }
                    if (settings.IncludeDnsPropagation) {
                        reportChecks.Add(HealthCheckType.DNSPROPAGATION);
                    }
                    await healthCheck.Verify(settings.Domain, reportChecks.ToArray(), cancellationToken: cancellationToken);
                    analyzeTask.Value = 100;
                    
                    // Step 2: Generate report + artifacts
                    cancellationToken.ThrowIfCancellationRequested();
                    var generateTask = ctx.AddTask("[yellow]Generating report + artifacts[/]");
                    
                    // Capture the run artifacts once, then send all report formats through one export batch.
                    var runDir = coord.End(healthCheck);
                    var conversionErrors = new List<string>();
                    var items = HealthCheckReportItems.BuildItems(healthCheck, settings.Domain, settings.StorePath, settings.IncludeDnsTrace, conversionErrors);
                    var exports = await ExportReportsAsync(settings, items, cancellationToken, healthCheck);
                    if (conversionErrors.Count > 0) {
                        AnsiConsole.MarkupLine("[yellow]Some report sections could not be converted and were skipped:[/]");
                        foreach (var error in conversionErrors.Distinct(StringComparer.OrdinalIgnoreCase).Take(25)) {
                            AnsiConsole.MarkupLine($"[yellow]- {Markup.Escape(error)}[/]");
                        }
                        if (conversionErrors.Count > 25) {
                            AnsiConsole.MarkupLine($"[yellow]... and {conversionErrors.Count - 25} more.[/]");
                        }
                    }

                    generateTask.Value = 100;

                    // Show summary
                    AnsiConsole.WriteLine();
                    var panel = new Panel(
                        $"[green]✓[/] Report generated successfully!\n" +
                        $"[blue]Domain:[/] {settings.Domain}\n" +
                        $"[blue]Formats:[/] {string.Join(", ", formats)}\n" +
                        $"[blue]Outputs:[/] {string.Join(", ", exports.Reports.Select(report => report.FilePath))}\n" +
                        $"[blue]Artifacts:[/] {runDir}\n" +
                        $"[blue]Template:[/] {settings.Template}\n" +
                        $"[blue]Theme:[/] {settings.Theme}"
                    ) {
                        Header = new PanelHeader("Report Generation Complete"),
                        Border = BoxBorder.Rounded
                    };
                    AnsiConsole.Write(panel);
                });
            
            return 0;
        }
        catch (Exception ex) {
            AnsiConsole.MarkupLine($"[red]Error generating report: {ex.Message}[/]");
            return 1;
        }
    }

    /// <summary>Validates CLI presentation options before progress, analysis or report writes begin.</summary>
    internal static IReadOnlyList<ReportFormat> ValidatePresentation(Settings settings) {
        if (settings == null) { throw new ArgumentNullException(nameof(settings)); }
        var requested = ReportFormatParser.Parse(settings.Formats);
        IReadOnlyList<ReportFormat> formats = requested.Count > 0 ? requested : new[] { ReportFormat.Html };
        if (!string.Equals(settings.Template?.Trim(), "default", StringComparison.OrdinalIgnoreCase)) {
            throw new InvalidOperationException("Assessment reports support only --template default. Remove the template override.");
        }
        if (!settings.IncludeTechnical) {
            throw new InvalidOperationException("Assessment reports include technical details; --technical=false is not supported.");
        }
        if (!settings.IncludeRecommendations) {
            throw new InvalidOperationException("Assessment reports include recommendations; --recommendations=false is not supported.");
        }
        string theme = (settings.Theme ?? string.Empty).Trim().ToLowerInvariant();
        if (formats.Contains(ReportFormat.Html)) {
            if (theme != "system" && theme != "light" && theme != "dark") {
                throw new InvalidOperationException("HTML reports support --theme system, light or dark.");
            }
        } else if (theme != "system") {
            throw new InvalidOperationException("--theme light and --theme dark apply only to HTML reports. Use --theme system for other formats.");
        }
        return formats;
    }

    /// <summary>Exports already-collected views through the same production path used after a CLI scan.</summary>
    internal static async Task<CompositionExportResult> ExportReportsAsync(Settings settings, IReadOnlyList<object> items,
        CancellationToken cancellationToken = default, DomainHealthCheck? healthCheck = null) {
        var formats = ValidatePresentation(settings);
        bool includeJson = formats.Contains(ReportFormat.Json);
        if (includeJson && healthCheck == null) {
            throw new ArgumentNullException(nameof(healthCheck), "The JSON report requires the collected health-check results.");
        }
        var assessmentFormats = formats.Where(format => format != ReportFormat.Json).ToArray();
        string? assessmentPath = includeJson && assessmentFormats.Length == 1 && assessmentFormats[0] == ReportFormat.MarkdownHtml
            ? ReportPathHelper.ResolveOutputPathForFormat(settings.OutputPath, null, settings.Domain, ReportFormat.MarkdownHtml, formats)
            : settings.OutputPath;
        var result = assessmentFormats.Length == 0 ? new CompositionExportResult {
            Items = items, Subjects = new[] { settings.Domain }, SubjectLabel = settings.Domain
        } : await CompositionExportService.ExportAsync(new CompositionExportRequest {
            Items = items, Formats = assessmentFormats, ExportPath = assessmentPath,
            Title = $"Security Report - {settings.Domain}", HtmlTheme = settings.Theme.Trim().ToLowerInvariant(),
            AutoCollectTtl = false, OpenInBrowser = settings.OpenInBrowser
        }, null, cancellationToken).ConfigureAwait(false);
        if (includeJson) {
            cancellationToken.ThrowIfCancellationRequested();
            // Keep the existing raw-analysis JSON contract; assessment JSON belongs to the composition API.
            string path = ReportPathHelper.ResolveOutputPathForFormat(settings.OutputPath, null,
                settings.Domain, ReportFormat.Json, formats);
            var json = await new ReportDispatcher().GenerateAsync(healthCheck!, new ReportOptions {
                Format = ReportFormat.Json, OutputPath = path
            }, settings.Domain).ConfigureAwait(false);
            result.Reports = result.Reports.Concat(new[] { json }).OrderBy(report => formats.ToList().IndexOf(report.Format)).ToArray();
        }
        if (result.Reports.Count == 0) { throw new InvalidOperationException("No completed report inputs are available to export."); }
        foreach (var report in result.Reports) { EnsureReportSucceeded(report); }
        return result;
    }

    internal static void EnsureReportSucceeded(ReportResult result)
    {
        if (result == null)
        {
            throw new ArgumentNullException(nameof(result));
        }

        if (!result.Success)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(result.ErrorMessage)
                ? "Report generation failed."
                : result.ErrorMessage);
        }
    }

}
