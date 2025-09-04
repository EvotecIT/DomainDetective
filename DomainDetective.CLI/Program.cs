using Spectre.Console;
using Spectre.Console.Cli;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using DomainDetective.CLI.Wizard;

namespace DomainDetective.CLI;

internal static class Program {
    internal static CancellationToken CancellationToken { get; private set; }

    [RequiresDynamicCode("Calls Spectre.Console.Cli.CommandApp.CommandApp(ITypeRegistrar)")]
    public static async Task<int> Main(string[] args) {
        // Ensure Unicode/emoji rendering and consistent input behavior
        try {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.InputEncoding = System.Text.Encoding.UTF8;
        } catch { /* ignore if not supported */ }
        using var cts = new CancellationTokenSource();
        CancellationToken = cts.Token;
        Console.CancelKeyPress += (_, e) => {
            e.Cancel = true;
            cts.Cancel();
        };

        // If no arguments provided, route to the interactive wizard by default
        // If arguments start with options (e.g., --domain), assume the 'wizard' command implicitly
        if (args.Length == 0) {
            args = new[] { "wizard", "--interactive", "--simple-ui", "--pause-exit" };
        } else if (args.Length > 0 && args[0].StartsWith("-") && args[0] != "--help" && args[0] != "-h") {
            var list = new List<string> { "wizard" };
            list.AddRange(args);
            args = list.ToArray();
        }

        var app = new CommandApp();
        app.Configure(config => {
            config.SetApplicationName("DomainDetective");
            config.AddExample(new[] { "check", "example.com" });
            config.AddExample(new[] { "wizard", "--domain", "example.com" });
            config.AddCommand<WizardScanCommand>("WizardScan")
                .WithDescription("Run the Hacker Wizard (parallel, animated)")
                .WithExample(new[] { "WizardScan", "--domain", "example.com", "--full", "--matrix" })
                .WithExample(new[] { "WizardScan", "--domain", "example.com", "--quick", "--output", "json" });
            // Friendly aliases
            config.AddCommand<WizardScanCommand>("wizard")
                .WithDescription("Run the Hacker Wizard (alias)")
                .WithExample(new[] { "wizard", "--domain", "example.com" });
            config.AddCommand<WizardScanCommand>("scan")
                .WithDescription("Run the Hacker Wizard (alias)")
                .WithExample(new[] { "scan", "--domain", "example.com" });
            config.AddCommand<CheckDomainCommand>("check")
                .WithDescription("Run domain health checks")
                .WithExample(new[] { "check", "example.com", "--json" })
                .WithExample(new[] { "check", "example.com", "--checks", "autodiscover" })
                .WithExample(new[] { "check", "example.com", "--port-profiles", "radius" });
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
            config.AddCommand<SearchDomainCommand>("SearchDomain")
                .WithDescription("Search for available domains")
                .WithExample(new[] { "SearchDomain", "mykeyword" });
            config.AddCommand<SearchEngineInfoCommand>("SearchEngineInfo")
                .WithDescription("Query search engine APIs")
                .WithExample(new[] { "SearchEngineInfo", "example", "--engine", "google" });
            config.AddCommand<SuggestDomainCommand>("SuggestDomain")
                .WithDescription("Suggest available domains")
                .WithExample(new[] { "SuggestDomain", "example.com" });
            config.AddCommand<TestSmimeaCommand>("TestSMIMEA")
                .WithDescription("Query SMIMEA record for an email address")
                .WithExample(new[] { "TestSMIMEA", "user@example.com" });
            config.AddCommand<TestRpkiCommand>("TestRPKI")
                .WithDescription("Validate RPKI origins for domain IPs")
                .WithExample(new[] { "TestRPKI", "example.com" });
            config.AddCommand<TestRdapCommand>("TestRDAP")
                .WithDescription("Query RDAP registration information")
                .WithExample(new[] { "TestRDAP", "example.com" });
            config.AddCommand<TestRdapIpCommand>("TestRDAP-IP")
                .WithDescription("Query RDAP information for an IP")
                .WithExample(new[] { "TestRDAP-IP", "192.0.2.1" });
            config.AddCommand<TestRdapAsCommand>("TestRDAP-AS")
                .WithDescription("Query RDAP information for an autonomous system")
                .WithExample(new[] { "TestRDAP-AS", "AS65536" });
            config.AddCommand<TestRdapEntityCommand>("TestRDAP-Entity")
                .WithDescription("Query RDAP information for an entity")
                .WithExample(new[] { "TestRDAP-Entity", "ABC123" });
            config.AddCommand<TestRdapNameserverCommand>("TestRDAP-NS")
                .WithDescription("Query RDAP information for a nameserver")
                .WithExample(new[] { "TestRDAP-NS", "ns1.example.com" });
            config.AddCommand<TestOpenResolverCommand>("TestOpenResolver")
                .WithDescription("Check DNS server for recursion")
                .WithExample(new[] { "TestOpenResolver", "8.8.8.8" });
            config.AddCommand<TestNtpServerCommand>("TestNtpServer")
                .WithDescription("Query NTP server for clock offset")
                .WithExample(new[] { "TestNtpServer", "--builtin", "Pool" });

            // Artifacts utilities
            config.AddCommand<DomainDetective.CLI.Commands.RunsListCommand>("RunsList")
                .WithDescription("List recent artifact runs (reads index.jsonl)")
                .WithExample(new[] { "RunsList", "--subject", "example.com" })
                .WithExample(new[] { "RunsList", "--count", "5" });
            config.AddCommand<DomainDetective.CLI.Commands.RunsOpenCommand>("RunsOpen")
                .WithDescription("Open most recent run directory or scan.json")
                .WithExample(new[] { "RunsOpen", "--subject", "example.com" })
                .WithExample(new[] { "RunsOpen", "--dir", "/path/to/run" });
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
