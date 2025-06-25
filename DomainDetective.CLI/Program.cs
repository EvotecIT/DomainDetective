using DomainDetective;
using Spectre.Console;
using System;
using System.Collections.Generic;
using System.Linq;
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
        ["dnsbl"] = HealthCheckType.DNSBL
    };

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help") || args.Contains("-h"))
        {
            ShowHelp();
            return 0;
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

        foreach (var domain in domains)
        {
            var hc = new DomainHealthCheck { Verbose = false };
            await hc.Verify(domain, checks);

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
                    _ => null
                };
                if (data != null)
                {
                    CliHelpers.ShowPropertiesTable($"{check} for {domain}", data);
                }
            }
        }

        return 0;
    }

    private static void ShowHelp()
    {
        AnsiConsole.MarkupLine("[green]DomainDetective CLI[/]");
        Console.WriteLine("Usage: ddcli [options] <domain> [domain...]");
        Console.WriteLine("--checks=LIST     Comma separated list of checks: dmarc, spf, dkim, mx, caa, ns, dane, dnssec, dnsbl");
        Console.WriteLine("--summary         Show condensed summary");
        Console.WriteLine("--json            Output raw JSON");
        Console.WriteLine("--smime=FILE      Parse S/MIME certificate file and exit");
    }
}
