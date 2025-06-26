using DomainDetective;
using Spectre.Console;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace DomainDetective.CLI;

/// <summary>
/// Entry point and command handling for the DomainDetective CLI.
/// </summary>
internal class Program
{
    private static readonly Dictionary<string, HealthCheckType> _options = new()
    {
        ["dmarc"] = HealthCheckType.DMARC,
        ["spf"] = HealthCheckType.SPF,
        ["dkim"] = HealthCheckType.DKIM,
        ["mx"] = HealthCheckType.MX,
        ["caa"] = HealthCheckType.CAA,
        ["ns"] = HealthCheckType.NS,
        ["zonetransfer"] = HealthCheckType.ZONETRANSFER,
        ["dane"] = HealthCheckType.DANE,
        ["dnssec"] = HealthCheckType.DNSSEC,
        ["dnsbl"] = HealthCheckType.DNSBL,
        ["contact"] = HealthCheckType.CONTACT
    };

    /// <summary>
    /// Application entry point.
    /// </summary>
    private static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("DomainDetective CLI");
        var domainsArg = new Argument<string[]>("domains") { Arity = ArgumentArity.ZeroOrMore };
        var checksOption = new Option<string[]>("--checks", "Comma separated list of checks")
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        var checkHttpOption = new Option<bool>("--check-http", "Perform plain HTTP check");
        var summaryOption = new Option<bool>("--summary", "Show condensed summary");
        var jsonOption = new Option<bool>("--json", "Output raw JSON");
        var smimeOption = new Option<FileInfo?>("--smime", "Parse S/MIME certificate file and exit");
        root.Add(domainsArg);
        root.Add(checksOption);
        root.Add(checkHttpOption);
        root.Add(summaryOption);
        root.Add(jsonOption);
        root.Add(smimeOption);

        var analyze = new Command("AnalyzeMessageHeader", "Analyze message header");
        var fileOpt = new Option<FileInfo?>("--file", "Header file");
        var headerOpt = new Option<string?>("--header", "Header text");
        var analyzeJson = new Option<bool>("--json", "Output raw JSON");
        analyze.Add(fileOpt);
        analyze.Add(headerOpt);
        analyze.Add(analyzeJson);
        analyze.SetAction(result =>
        {
            var file = result.GetValue(fileOpt);
            var header = result.GetValue(headerOpt);
            var json = result.GetValue(analyzeJson);
            AnalyzeMessageHeader(file, header, json);
        });
        root.Add(analyze);

        root.SetAction(async result =>
        {
            var domains = result.GetValue(domainsArg);
            var checks = result.GetValue(checksOption) ?? Array.Empty<string>();
            var checkHttp = result.GetValue(checkHttpOption);
            var summary = result.GetValue(summaryOption);
            var json = result.GetValue(jsonOption);
            var smime = result.GetValue(smimeOption);

            if (smime != null)
            {
                var smimeAnalysis = new SmimeCertificateAnalysis();
                smimeAnalysis.AnalyzeFile(smime.FullName);
                CliHelpers.ShowPropertiesTable($"S/MIME certificate {smime.FullName}", smimeAnalysis);
                return;
            }

            if (domains.Length == 0)
            {
                await RunWizard();
                return;
            }

            var selected = new List<HealthCheckType>();
            foreach (var check in checks.SelectMany(c => c.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            {
                if (_options.TryGetValue(check.ToLowerInvariant(), out var type))
                {
                    selected.Add(type);
                }
            }

            var arr = selected.Count > 0 ? selected.ToArray() : null;
            await RunChecks(domains, arr, checkHttp, json, summary);
        });

        var config = new CommandLineConfiguration(root);
        return await config.InvokeAsync(args);
    }

    /// <summary>
    /// Analyzes an email message header and prints the results.
    /// </summary>
    private static void AnalyzeMessageHeader(FileInfo? file, string? header, bool json)
    {
        string? headerText = null;
        if (file != null)
        {
            if (!file.Exists)
            {
                AnsiConsole.MarkupLine($"[red]File not found: {file.FullName}[/]");
                return;
            }
            headerText = File.ReadAllText(file.FullName);
        }
        else if (!string.IsNullOrWhiteSpace(header))
        {
            headerText = header;
        }

        if (string.IsNullOrWhiteSpace(headerText))
        {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return;
        }

        var hc = new DomainHealthCheck();
        var result = hc.CheckMessageHeaders(headerText);

        if (json)
        {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        }
        else
        {
            CliHelpers.ShowPropertiesTable("Message Header Analysis", result);
        }
    }

    /// <summary>
    /// Interactive wizard to collect parameters from the user.
    /// </summary>
    private static async Task<int> RunWizard()
    {
        AnsiConsole.MarkupLine("[green]DomainDetective CLI Wizard[/]");
        var domainInput = AnsiConsole.Prompt(new TextPrompt<string>("Enter domain(s) [comma separated]:")
            .Validate(input => string.IsNullOrWhiteSpace(input)
                ? ValidationResult.Error("[red]Domain is required[/]")
                : ValidationResult.Success()));
        var domains = domainInput.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var checkPrompt = new MultiSelectionPrompt<string>()
            .Title("Select checks to run")
            .NotRequired()
            .InstructionsText("[grey](Press <space> to toggle, <enter> to accept)[/]")
            .AddChoices(_options.Keys);

        var selected = AnsiConsole.Prompt(checkPrompt);
        var checks = selected.Count > 0 ? selected.Select(c => _options[c]).ToArray() : null;

        var outputJson = AnsiConsole.Confirm("Output JSON?");
        var summaryOnly = !outputJson && AnsiConsole.Confirm("Show condensed summary?");
        var checkHttp = AnsiConsole.Confirm("Perform plain HTTP check?");

        await RunChecks(domains, checks, checkHttp, outputJson, summaryOnly);
        return 0;
    }

    /// <summary>
    /// Runs the selected health checks for the provided domains.
    /// </summary>
    private static async Task RunChecks(string[] domains, HealthCheckType[]? checks, bool checkHttp, bool outputJson, bool summaryOnly)
    {
        foreach (var domain in domains)
        {
            var hc = new DomainHealthCheck { Verbose = false };
            await hc.Verify(domain, checks);
            if (checkHttp)
            {
                await hc.VerifyPlainHttp(domain);
            }

            if (outputJson)
            {
                Console.WriteLine(hc.ToJson());
                continue;
            }

            if (summaryOnly)
            {
                var summary = hc.BuildSummary();
                CliHelpers.ShowPropertiesTable($"Summary for {domain}", summary);
                continue;
            }

            var activeChecks = checks ?? _options.Values.ToArray();
            foreach (var check in activeChecks)
            {
                object? data = check switch
                {
                    HealthCheckType.DMARC => hc.DmarcAnalysis,
                    HealthCheckType.SPF => hc.SpfAnalysis,
                    HealthCheckType.DKIM => hc.DKIMAnalysis,
                    HealthCheckType.MX => hc.MXAnalysis,
                    HealthCheckType.CAA => hc.CAAAnalysis,
                    HealthCheckType.NS => hc.NSAnalysis,
                    HealthCheckType.ZONETRANSFER => hc.ZoneTransferAnalysis,
                    HealthCheckType.DANE => hc.DaneAnalysis,
                    HealthCheckType.DNSBL => hc.DNSBLAnalysis,
                    HealthCheckType.DNSSEC => hc.DNSSecAnalysis,
                    HealthCheckType.CONTACT => hc.ContactInfoAnalysis,
                    _ => null
                };
                if (data != null)
                {
                    var desc = DomainHealthCheck.GetCheckDescription(check);
                    var header = desc != null ? $"{check} for {domain} - {desc.Summary}" : $"{check} for {domain}";
                    CliHelpers.ShowPropertiesTable(header, data);
                }
            }
            if (checkHttp)
            {
                CliHelpers.ShowPropertiesTable($"PLAIN HTTP for {domain}", hc.HttpAnalysis);
            }
        }
    }
}
