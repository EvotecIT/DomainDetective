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
                .WithDescription("Run domain health checks")
                .WithExample(new[] { "check", "example.com", "--json" })
                .WithExample(new[] { "check", "example.com", "--checks", "autodiscover" });
            config.AddCommand<AnalyzeMessageHeaderCommand>("AnalyzeMessageHeader")
                .WithDescription("Analyze message header")
                .WithExample(new[] { "AnalyzeMessageHeader", "--file", "./headers.txt", "--json" });
            config.AddCommand<AnalyzeArcCommand>("AnalyzeARC")
                .WithDescription("Analyze ARC headers")
                .WithExample(new[] { "AnalyzeARC", "--file", "./headers.txt", "--json" });
            config.AddCommand<WhoisCommand>("Whois")
                .WithDescription("Query WHOIS information")
                .WithExample(new[] { "Whois", "example.com" })
                .WithExample(new[] { "Whois", "example.com", "--snapshot-path", "./whois", "--diff" });
            config.AddCommand<AnalyzeDnsTunnelingCommand>("AnalyzeDnsTunneling")
                .WithDescription("Analyze DNS logs for tunneling patterns")
                .WithExample(new[] { "AnalyzeDnsTunneling", "--domain", "example.com", "--file", "dns.log" });
            config.AddCommand<DnsPropagationCommand>("DnsPropagation")
                .WithDescription("Check DNS propagation across public resolvers")
                .WithExample(new[] { "DnsPropagation", "--domain", "example.com", "--record-type", "A" });
            config.AddCommand<BuildDmarcCommand>("BuildDmarcRecord")
                .WithDescription("Interactively build a DMARC record")
                .WithExample(new[] { "BuildDmarcRecord" });
            config.AddCommand<ImportDmarcForensicCommand>("ImportDmarcForensic")
                .WithDescription("Import DMARC forensic reports")
                .WithExample(new[] { "ImportDmarcForensic", "forensic.zip" });
            config.AddCommand<RefreshSuffixListCommand>("RefreshSuffixList")
                .WithDescription("Download the latest public suffix list")
                .WithExample(new[] { "RefreshSuffixList", "--force" });
            config.AddCommand<TestSmimeaCommand>("TestSMIMEA")
                .WithDescription("Query SMIMEA record for an email address")
                .WithExample(new[] { "TestSMIMEA", "user@example.com" });
            config.AddCommand<TestRpkiCommand>("TestRPKI")
                .WithDescription("Validate RPKI origins for domain IPs")
                .WithExample(new[] { "TestRPKI", "example.com" });
            config.AddCommand<TestRdapCommand>("TestRDAP")
                .WithDescription("Query RDAP registration information")
                .WithExample(new[] { "TestRDAP", "example.com" });
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
