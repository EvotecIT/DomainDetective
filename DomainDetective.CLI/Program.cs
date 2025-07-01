using Spectre.Console;
using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;
using System.IO;

namespace DomainDetective.CLI;

internal static class Program {
    internal static CancellationToken CancellationToken { get; private set; }

    [RequiresDynamicCode("Calls Spectre.Console.Cli.CommandApp.CommandApp(ITypeRegistrar)")]
    public static async Task<int> Main(string[] args) {
        using var cts = new CancellationTokenSource();
        CancellationToken = cts.Token;
        Console.CancelKeyPress += (_, e) => {
            e.Cancel = true;
            cts.Cancel();
        };

        var app = new CommandApp();
        app.Configure(config => {
            config.SetApplicationName("DomainDetective");
            config.AddCommand<CheckDomainCommand>("check")
                .WithDescription("Run domain health checks");
            config.AddCommand<AnalyzeMessageHeaderCommand>("AnalyzeMessageHeader")
                .WithDescription("Analyze message header");
            config.AddCommand<AnalyzeArcCommand>("AnalyzeARC")
                .WithDescription("Analyze ARC headers");
            config.AddCommand<WhoisCommand>("Whois")
                .WithDescription("Query WHOIS information");
            config.AddCommand<AnalyzeDnsTunnelingCommand>("AnalyzeDnsTunneling")
                .WithDescription("Analyze DNS logs for tunneling patterns");
            config.AddCommand<DnsPropagationCommand>("DnsPropagation")
                .WithDescription("Check DNS propagation across public resolvers");
            config.AddCommand<BuildDmarcCommand>("BuildDmarcRecord")
                .WithDescription("Interactively build a DMARC record");
            config.AddCommand<RefreshSuffixListCommand>("RefreshSuffixList")
                .WithDescription("Download the latest public suffix list");
            config.AddCommand<TestSmimeaCommand>("TestSMIMEA")
                .WithDescription("Query SMIMEA record for an email address");
        });
        try {
            return await app.RunAsync(args).WaitAsync(cts.Token);
        } catch (FileNotFoundException ex) {
            AnsiConsole.MarkupLine($"[red]{ex.Message}[/]");
            return 1;
        } catch (OperationCanceledException) {
            AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            return 1;
        }
    }
}
