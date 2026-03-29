using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Cli;
using DomainDetective.Reports;
using DomainDetective.Reports.Artifacts;
using DomainDetective.Reports.Html;
using DomainDetective.Reports.Office;
using DomainDetective.TimeSeries.DmarcAggregate;
using DomainDetective.TimeSeries.Registration;
using DomainDetective.TimeSeries.TlsRpt;
using HtmlForgeX;
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
        
        [Description("Report output (html, json, word, excel, pdf, markdown, markdownhtml)")]
        [CommandOption("-f|--format|--report <FORMAT>")]
        [DefaultValue("html")]
        public string Format { get; set; } = "html";
        
        [Description("Output file path")]
        [CommandOption("-o|--output <PATH>")]
        public string? OutputPath { get; set; }
        
        [Description("Report template (default, executive, technical, compliance)")]
        [CommandOption("-t|--template <TEMPLATE>")]
        [DefaultValue("default")]
        public string Template { get; set; } = "default";
        
        [Description("Report theme (light, dark, professional)")]
        [CommandOption("--theme <THEME>")]
        [DefaultValue("light")]
        public string Theme { get; set; } = "light";
        
        [Description("Open report in browser after generation")]
        [CommandOption("--open")]
        [DefaultValue(true)]
        public bool OpenInBrowser { get; set; } = true;
        
        [Description("Include technical details")]
        [CommandOption("--technical")]
        [DefaultValue(true)]
        public bool IncludeTechnical { get; set; } = true;
        
        [Description("Include recommendations")]
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
    
    public override async Task<int> ExecuteAsync(CommandContext context, Settings settings) {
        try {
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
	                    };
                    if (settings.IncludeDnsTrace) {
                        reportChecks.Add(HealthCheckType.DNSTRACE);
                    }
                    if (settings.IncludeDnsPropagation) {
                        reportChecks.Add(HealthCheckType.DNSPROPAGATION);
                    }
                    await healthCheck.Verify(settings.Domain, reportChecks.ToArray());
                    analyzeTask.Value = 100;
                    
                    // Step 2: Generate report + artifacts
                    var generateTask = ctx.AddTask("[yellow]Generating report + artifacts[/]");
                    
                    // Determine output path
                    var fmt = settings.Format?.ToLowerInvariant() ?? "html";
                    var formatEnum = fmt switch {
                        "html" => ReportFormat.Html,
                        "json" => ReportFormat.Json,
                        "word" => ReportFormat.Word,
                        "excel" => ReportFormat.Excel,
                        "pdf" => ReportFormat.Pdf,
                        "markdown" => ReportFormat.Markdown,
                        "markdownhtml" => ReportFormat.MarkdownHtml,
                        _ => ReportFormat.Html
                    };
                    var outputPath = DomainDetective.Reports.ReportPathHelper.ResolveOutputPath(settings.OutputPath, null, settings.Domain, formatEnum);
                    
                    // Always emit JSON artifacts for the run.
                    var runDir = coord.End(healthCheck);

	                    // HTML/Word: use composition generators for parity with PowerShell export.
	                    if (formatEnum == ReportFormat.Html || formatEnum == ReportFormat.Word)
	                    {
	                        var conversionErrors = new List<string>();
	                        var items = BuildCompositionItems(healthCheck, settings.Domain, settings.StorePath, settings.IncludeDnsTrace, conversionErrors);
	
	                        if (formatEnum == ReportFormat.Word)
	                        {
	                            WordCompositionReport.Generate(
	                                outputPath,
                                items,
                                ReportScope.Normal,
                                showInfoFindings: true,
                                narrativePlacement: NarrativePlacement.Auto,
                                titleOverride: $"Security Report — {settings.Domain}");

                            if (settings.OpenInBrowser)
                            {
                                TryOpenWithShell(outputPath);
                            }
                        }
                        else
                        {
                            var profile = (settings.Template ?? "default").Equals("executive", StringComparison.OrdinalIgnoreCase)
                                ? HtmlProfile.Dashboard
                                : HtmlProfile.Document;
                            var themeMode = (settings.Theme ?? "light").Equals("dark", StringComparison.OrdinalIgnoreCase)
                                ? ThemeMode.Dark
                                : ThemeMode.Light;

                            HtmlCompositionReport.Generate(
                                outputPath,
                                items,
                                ReportScope.Normal,
                                openInBrowser: settings.OpenInBrowser,
                                narrativePlacement: NarrativePlacement.Auto,
                                titleOverride: $"Security Report — {settings.Domain}",
                                authorOverride: "DomainDetective CLI",
                                descriptionOverride: "Domain security posture overview",
	                                profile: profile,
	                                themeMode: themeMode);
	                        }

	                        if (conversionErrors.Count > 0)
	                        {
	                            AnsiConsole.MarkupLine("[yellow]Some report sections could not be converted and were skipped:[/]");
	                            foreach (var error in conversionErrors.Distinct(StringComparer.OrdinalIgnoreCase).Take(25))
	                            {
	                                AnsiConsole.MarkupLine($"[yellow]- {Markup.Escape(error)}[/]");
	                            }
	                            if (conversionErrors.Count > 25)
	                            {
	                                AnsiConsole.MarkupLine($"[yellow]... and {conversionErrors.Count - 25} more.[/]");
	                            }
	                        }
	                    }
                    else
                    {
                        // Fallback: use the IReportGenerator adapter (may be minimal depending on the format).
                        var dispatcher = new ReportDispatcher();
                        var options = new ReportOptions
                        {
                            Format = formatEnum,
                            OutputPath = outputPath
                        };
                        options.CustomProperties["Domain"] = settings.Domain;
                        options.CustomProperties["OpenInBrowser"] = settings.OpenInBrowser;
                        var result = await dispatcher.GenerateAsync(healthCheck, options, settings.Domain, settings.OpenInBrowser);
                        EnsureReportSucceeded(result);
                    }

                    generateTask.Value = 100;

                    // Show summary
                    AnsiConsole.WriteLine();
                    var panel = new Panel(
                        $"[green]✓[/] Report generated successfully!\n" +
                        $"[blue]Domain:[/] {settings.Domain}\n" +
                        $"[blue]Format:[/] {settings.Format}\n" +
                        $"[blue]Output:[/] {outputPath}\n" +
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

    private static List<object> BuildCompositionItems(DomainHealthCheck healthCheck, string domain, string? storePath, bool includeDnsTrace, List<string> conversionErrors)
    {
        var items = new List<object>();
        if (conversionErrors == null)
        {
            throw new ArgumentNullException(nameof(conversionErrors));
        }

        // Core DNS/mail policy checks from this run
        void TryAdd(string name, Func<object> factory)
        {
            try
            {
                items.Add(factory());
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"{name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        void TryAddRange<T>(string name, Func<IEnumerable<T>> factory)
        {
            try
            {
                var values = factory();
                if (values != null)
                {
                    items.AddRange(values.Cast<object>());
                }
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"{name}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        TryAdd("MX", () => DomainDetective.Views.Converters.Convert(healthCheck.MXAnalysis));
        TryAdd("SPF", () => DomainDetective.Views.Converters.Convert(healthCheck.SpfAnalysis));
        TryAddRange("DKIM", () => DomainDetective.Views.Converters.Convert(healthCheck.DKIMAnalysis));
        TryAdd("DMARC", () => DomainDetective.Views.Converters.Convert(healthCheck.DmarcAnalysis));
        TryAdd("TYPOSQUATTING", () => DomainDetective.Views.Converters.Convert(healthCheck.TyposquattingAnalysis));
        TryAdd("CAA", () => DomainDetective.Views.Converters.Convert(healthCheck.CAAAnalysis));
        TryAdd("DNSBL", () => DomainDetective.Views.Converters.Convert(healthCheck.DNSBLAnalysis));
        TryAdd("RPKI", () => DomainDetective.Views.Converters.Convert(healthCheck.RpkiAnalysis));
        TryAdd("NS", () => DomainDetective.Views.Converters.Convert(healthCheck.NSAnalysis));
        TryAdd("SOA", () => DomainDetective.Views.Converters.Convert(healthCheck.SOAAnalysis));
        TryAdd("TTL", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsTtlAnalysis));
        TryAdd("ZONETRANSFER", () => DomainDetective.Views.Converters.Convert(healthCheck.ZoneTransferAnalysis));
        TryAdd("WILDCARDDNS", () => DomainDetective.Views.Converters.Convert(healthCheck.WildcardDnsAnalysis));
        TryAdd("MTASTS", () => DomainDetective.Views.Converters.Convert(healthCheck.MTASTSAnalysis));
        TryAdd("TLSRPT", () => DomainDetective.Views.Converters.Convert(healthCheck.TLSRPTAnalysis));
        TryAdd("DANE", () => DomainDetective.Views.Converters.Convert(healthCheck.DaneAnalysis));
        TryAdd("DNSSEC", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsSecAnalysis));
        TryAdd("CTTIMELINE", () => DomainDetective.Views.Converters.Convert(healthCheck.CtTimelineAnalysis));
        TryAdd("SUBDOMAINS", () => DomainDetective.Views.Converters.Convert(healthCheck.SubdomainsAnalysis));
        TryAdd("DNSINVENTORY", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsInventoryAnalysis));
        TryAdd("DNSAMPLIFICATION", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsAmplificationAnalysis));
        TryAdd("DNSOVERTLS", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsOverTlsAnalysis));
        if (!string.IsNullOrWhiteSpace(healthCheck.HttpAnalysis.Subject))
        {
            TryAdd("HTTP", () => DomainDetective.Views.Converters.Convert(healthCheck.HttpAnalysis));
        }
        if (!string.IsNullOrWhiteSpace(healthCheck.IpEnrichmentAnalysis.Subject))
        {
            TryAdd("IPENRICHMENT", () => DomainDetective.Views.Converters.Convert(healthCheck.IpEnrichmentAnalysis));
        }
        try
        {
            var set = healthCheck.DnsPropagationSet;
            if (set != null && set.Items.Count > 0)
            {
                foreach (var a in set.Items)
                {
                    TryAdd("DNSPROPAGATION", () => DomainDetective.Views.Converters.Convert(a));
                }
            }
        }
        catch (Exception ex)
        {
            conversionErrors.Add($"DNSPROPAGATION: {ex.GetType().Name}: {ex.Message}");
        }
        if (includeDnsTrace)
        {
            TryAdd("DNSTRACE", () => DomainDetective.Views.Converters.Convert(healthCheck.DnsTraceAnalysis));
        }

        // Optional time-series sections from a store (only when data exists)
        if (!string.IsNullOrWhiteSpace(storePath))
        {
            try
            {
                var dmarcStore = new DmarcAggregateTimeSeriesStore(storePath!);
                var snaps = dmarcStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"DMARC-AGGREGATE-STORE: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                var tlsStore = new TlsRptTimeSeriesStore(storePath!);
                var snaps = tlsStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"TLSRPT-STORE: {ex.GetType().Name}: {ex.Message}");
            }

            try
            {
                var regStore = new RegistrationTimeSeriesStore(storePath!);
                var snaps = regStore.LoadSnapshots(domain);
                if (snaps.Count > 0) items.Add(DomainDetective.Views.Converters.Convert(snaps, domain));
            }
            catch (Exception ex)
            {
                conversionErrors.Add($"REGISTRATION-STORE: {ex.GetType().Name}: {ex.Message}");
            }
        }

        // Composition generators require at least one supported view object.
        if (items.Count == 0)
        {
            TryAdd("MX", () => DomainDetective.Views.Converters.Convert(healthCheck.MXAnalysis));
        }

        return items;
    }

    private static void TryOpenWithShell(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch { }
    }
}
