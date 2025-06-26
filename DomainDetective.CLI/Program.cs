using DomainDetective;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.IO;
using System.Threading.Tasks;

namespace DomainDetective.CLI;

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
        ["dane"] = HealthCheckType.DANE,
        ["dnssec"] = HealthCheckType.DNSSEC,
        ["dnsbl"] = HealthCheckType.DNSBL,
        ["contact"] = HealthCheckType.CONTACT
    };

    private static async Task<int> Main(string[] args)
    {
        if (args.Contains("--help") || args.Contains("-h"))
        {
            ShowHelp();
            return 0;
        }

        if (args.Length > 0 && args[0].Equals("AnalyzeMessageHeader", StringComparison.OrdinalIgnoreCase))
        {
            return AnalyzeMessageHeader(args.Skip(1).ToArray());
        }

        if (args.Length == 0)
        {
            return await RunWizard();
        }

        var smimePath = args.FirstOrDefault(a => a.StartsWith("--smime="));
        if (smimePath != null)
        {
            var file = smimePath.Substring("--smime=".Length);
            var smime = new SmimeCertificateAnalysis();
            smime.AnalyzeFile(file);
            CliHelpers.ShowPropertiesTable($"S/MIME certificate {file}", smime);
            return 0;
        }

        var outputJson = args.Contains("--json");
        var summaryOnly = args.Contains("--summary");
        var checkHttp = args.Contains("--check-http");

        var checksOption = args.FirstOrDefault(a => a.StartsWith("--checks="));
        var selectedChecks = new List<HealthCheckType>();
        if (checksOption != null)
        {
            var parts = checksOption.Substring("--checks=".Length)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (_options.TryGetValue(part.ToLowerInvariant(), out var type))
                {
                    selectedChecks.Add(type);
                }
            }
        }

        var domains = args.Where(a => !a.StartsWith("--")).ToArray();
        if (domains.Length == 0)
        {
            AnsiConsole.MarkupLine("[red]No domain provided.[/]");
            return 1;
        }

        var checks = selectedChecks.Count > 0 ? selectedChecks.ToArray() : null;
        await RunChecks(domains, checks, checkHttp, outputJson, summaryOnly);

        return 0;
    }

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
                    HealthCheckType.DANE => hc.DaneAnalysis,
                    HealthCheckType.DNSBL => hc.DNSBLAnalysis,
                    HealthCheckType.DNSSEC => hc.DNSSecAnalysis,
                    HealthCheckType.CONTACT => hc.ContactInfoAnalysis,
                    _ => null
                };
                if (data != null)
                {
                    var desc = DomainHealthCheck.GetCheckDescription(check);
                    var header = desc != null
                        ? $"{check} for {domain} - {desc.Summary}"
                        : $"{check} for {domain}";
                    CliHelpers.ShowPropertiesTable(header, data);
                }
            }
            if (checkHttp)
            {
                CliHelpers.ShowPropertiesTable($"PLAIN HTTP for {domain}", hc.HttpAnalysis);
            }
        }
    }

    private static int AnalyzeMessageHeader(string[] args)
    {
        var outputJson = args.Contains("--json");
        var fileArg = args.FirstOrDefault(a => a.StartsWith("--file="));
        var textArg = args.FirstOrDefault(a => a.StartsWith("--header="));

        string? headerText = null;

        if (fileArg != null)
        {
            var path = fileArg.Substring("--file=".Length);
            if (!File.Exists(path))
            {
                AnsiConsole.MarkupLine($"[red]File not found: {path}[/]");
                return 1;
            }
            headerText = File.ReadAllText(path);
        }
        else if (textArg != null)
        {
            headerText = textArg.Substring("--header=".Length);
        }

        if (string.IsNullOrWhiteSpace(headerText))
        {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return 1;
        }

        var hc = new DomainHealthCheck();
        var result = hc.CheckMessageHeaders(headerText);

        if (outputJson)
        {
            var json = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(json);
        }
        else
        {
            CliHelpers.ShowPropertiesTable("Message Header Analysis", result);
        }

        return 0;
    }

    private static void ShowHelp()
    {
        AnsiConsole.MarkupLine("[green]DomainDetective CLI[/]");
        Console.WriteLine("Usage: ddcli [options] <domain> [domain...]");
        Console.WriteLine("--checks=LIST     Comma separated list of checks: dmarc, spf, dkim, mx, caa, ns, dane, dnssec, dnsbl, contact");
        Console.WriteLine("--check-http      Perform plain HTTP check");
        Console.WriteLine("--summary         Show condensed summary");
        Console.WriteLine("--json            Output raw JSON");
        Console.WriteLine("--smime=FILE      Parse S/MIME certificate file and exit");
        Console.WriteLine("AnalyzeMessageHeader [--file=PATH|--header=TEXT] [--json]");
    }
}
