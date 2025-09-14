using System;
using System.ComponentModel;
using System.Threading.Tasks;
using Spectre.Console;
using Spectre.Console.Cli;
using DomainDetective.Reports;
using DomainDetective.Reports.Artifacts;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// CLI command for generating domain security reports
/// </summary>
internal sealed class GenerateReportCommand : AsyncCommand<GenerateReportCommand.Settings> {
    public sealed class Settings : CommandSettings {
        [Description("Domain to analyze")]
        [CommandArgument(0, "<domain>")]
        public string Domain { get; set; } = string.Empty;
        
        [Description("Report output (html, json, word, excel, pdf, markdown, htmlAsMarkdown)")]
        [CommandOption("-f|--format|--report")]
        [DefaultValue("html")]
        public string Format { get; set; } = "html";
        
        [Description("Output file path")]
        [CommandOption("-o|--output")]
        public string? OutputPath { get; set; }
        
        [Description("Report template (default, executive, technical, compliance)")]
        [CommandOption("-t|--template")]
        [DefaultValue("default")]
        public string Template { get; set; } = "default";
        
        [Description("Report theme (light, dark, professional)")]
        [CommandOption("--theme")]
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
                    var healthCheck = new DomainHealthCheck();
                    var logger = new InternalLogger(false);
                    // Use same logger in health check for consistent events
                    healthCheck = new DomainHealthCheck(healthCheck.DnsEndpoint, logger);
                    var artifactsBase = DomainDetective.Reports.FilePathHelper.ResolveBaseDirectory(settings.OutputPath, null);
                    using var coord = RunCoordinator.Begin(settings.Domain, logger, artifactsBase);
                    await healthCheck.Verify(settings.Domain);
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
                    
                    // Generate report and write artifacts (centralized)
                    var options = new ReportOptions {
                        Format = formatEnum,
                        OutputPath = outputPath
                    };
                    options.CustomProperties["Domain"] = settings.Domain;
                    options.CustomProperties["OpenInBrowser"] = settings.OpenInBrowser;
                    var (dir, result) = await coord.EndAndExportAsync(
                        healthCheck,
                        options,
                        settings.Domain,
                        settings.OpenInBrowser);
                    if (!result.Success) {
                        AnsiConsole.MarkupLine($"[red]{result.ErrorMessage}[/]");
                        return;
                    }

                    generateTask.Value = 100;

                    // Show summary
                    AnsiConsole.WriteLine();
                    var panel = new Panel(
                        $"[green]✓[/] Report generated successfully!\n" +
                        $"[blue]Domain:[/] {settings.Domain}\n" +
                        $"[blue]Format:[/] {settings.Format}\n" +
                        $"[blue]Output:[/] {outputPath}\n" +
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
}
