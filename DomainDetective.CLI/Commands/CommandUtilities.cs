using DomainDetective;
using Spectre.Console;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace DomainDetective.CLI;

internal static class CommandUtilities {
    internal static readonly Dictionary<string, HealthCheckType> Options = new() {
        ["dmarc"] = HealthCheckType.DMARC,
        ["spf"] = HealthCheckType.SPF,
        ["dkim"] = HealthCheckType.DKIM,
        ["mx"] = HealthCheckType.MX,
        ["caa"] = HealthCheckType.CAA,
        ["ns"] = HealthCheckType.NS,
        ["delegation"] = HealthCheckType.DELEGATION,
        ["zonetransfer"] = HealthCheckType.ZONETRANSFER,
        ["dane"] = HealthCheckType.DANE,
        ["dnssec"] = HealthCheckType.DNSSEC,
        ["dnsbl"] = HealthCheckType.DNSBL,
        ["contact"] = HealthCheckType.CONTACT,
        ["arc"] = HealthCheckType.ARC,
        ["danglingcname"] = HealthCheckType.DANGLINGCNAME,
        ["banner"] = HealthCheckType.SMTPBANNER,
        ["rdns"] = HealthCheckType.REVERSEDNS,
        ["fcrdns"] = HealthCheckType.FCRDNS,
        ["autodiscover"] = HealthCheckType.AUTODISCOVER,
        ["ports"] = HealthCheckType.PORTAVAILABILITY,
        ["portscan"] = HealthCheckType.PORTSCAN,
        ["ipneighbor"] = HealthCheckType.IPNEIGHBOR,
        ["dnstunneling"] = HealthCheckType.DNSTUNNELING,
        ["wildcarddns"] = HealthCheckType.WILDCARDDNS,
        ["edns"] = HealthCheckType.EDNSSUPPORT
    };

    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    internal static void AnalyzeMessageHeader(FileInfo? file, string? header, bool json) {
        string? headerText = null;
        if (file != null) {
            if (!file.Exists) {
                AnsiConsole.MarkupLine($"[red]File not found: {file.FullName}[/]");
                return;
            }
            headerText = File.ReadAllText(file.FullName);
        } else if (!string.IsNullOrWhiteSpace(header)) {
            headerText = header;
        }

        if (string.IsNullOrWhiteSpace(headerText)) {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return;
        }

        var hc = new DomainHealthCheck();
        var result = hc.CheckMessageHeaders(headerText);

        if (json) {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        } else {
            CliHelpers.ShowPropertiesTable("Message Header Analysis", result, false);
        }
    }

    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    internal static void AnalyzeARC(FileInfo? file, string? header, bool json) {
        string? headerText = null;
        if (file != null) {
            if (!file.Exists) {
                AnsiConsole.MarkupLine($"[red]File not found: {file.FullName}[/]");
                return;
            }
            headerText = File.ReadAllText(file.FullName);
        } else if (!string.IsNullOrWhiteSpace(header)) {
            headerText = header;
        }

        if (string.IsNullOrWhiteSpace(headerText)) {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return;
        }

        var hc = new DomainHealthCheck();
        var result = hc.VerifyARC(headerText);

        if (json) {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        } else {
            CliHelpers.ShowPropertiesTable("ARC Analysis", result, false);
        }
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    internal static void AnalyzeDnsTunneling(string domain, string filePath, bool json) {
        if (!File.Exists(filePath)) {
            AnsiConsole.MarkupLine($"[red]File not found: {filePath}[/]");
            return;
        }
        var lines = File.ReadAllLines(filePath);
        var hc = new DomainHealthCheck { DnsTunnelingLogs = lines };
        hc.CheckDnsTunneling(domain);
        var result = hc.DnsTunnelingAnalysis;
        if (json) {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        } else {
            CliHelpers.ShowPropertiesTable($"DNS Tunneling for {domain}", result, false);
        }
    }

    internal static async Task<int> RunWizard() {
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
            .AddChoices(Options.Keys);

        var selected = AnsiConsole.Prompt(checkPrompt);
        var checks = selected.Count > 0 ? selected.Select(c => Options[c]).ToArray() : null;

        var outputJson = AnsiConsole.Confirm("Output JSON?");
        var summaryOnly = !outputJson && AnsiConsole.Confirm("Show condensed summary?");
        var checkHttp = AnsiConsole.Confirm("Perform plain HTTP check?");
        var subPolicy = AnsiConsole.Confirm("Evaluate subdomain policy?");

        await RunChecks(domains, checks, checkHttp, outputJson, summaryOnly, subPolicy, false, null);
        return 0;
    }

    internal static async Task RunChecks(string[] domains, HealthCheckType[]? checks, bool checkHttp, bool outputJson, bool summaryOnly, bool subdomainPolicy, bool unicodeOutput, int[]? danePorts) {
        foreach (var domain in domains) {
            var logger = new InternalLogger();
            var hc = new DomainHealthCheck(internalLogger: logger) { Verbose = false, UseSubdomainPolicy = subdomainPolicy, UnicodeOutput = unicodeOutput };
            var needsPortScan = checks?.Contains(HealthCheckType.PORTSCAN) ?? false;
            if (needsPortScan) {
                await AnsiConsole.Progress().StartAsync(async ctx => {
                    ProgressTask? task = null;
                    void Handler(object? _, LogEventArgs e) {
                        if (e.ProgressActivity == "PortScan" && e.ProgressTotalSteps.HasValue && e.ProgressCurrentSteps.HasValue) {
                            task ??= ctx.AddTask($"Port scan for {domain}", maxValue: e.ProgressTotalSteps.Value);
                            task.Value = e.ProgressCurrentSteps.Value;
                        }
                    }

                    logger.OnProgressMessage += Handler;
                    try {
                        await hc.Verify(domain, checks, null, null, danePorts);
                        if (checkHttp) {
                            await hc.VerifyPlainHttp(domain);
                        }
                    } finally {
                        logger.OnProgressMessage -= Handler;
                    }
                });
            } else {
                await hc.Verify(domain, checks, null, null, danePorts);
                if (checkHttp) {
                    await hc.VerifyPlainHttp(domain);
                }
            }

            if (outputJson) {
                Console.WriteLine(hc.ToJson());
                continue;
            }

            if (summaryOnly) {
                var summary = hc.BuildSummary();
                CliHelpers.ShowPropertiesTable($"Summary for {domain}", summary, unicodeOutput);
                continue;
            }

            var activeChecks = checks ?? Options.Values.ToArray();
            foreach (var check in activeChecks) {
                object? data = check switch {
                    HealthCheckType.DMARC => hc.DmarcAnalysis,
                    HealthCheckType.SPF => hc.SpfAnalysis,
                    HealthCheckType.DKIM => hc.DKIMAnalysis,
                    HealthCheckType.MX => hc.MXAnalysis,
                    HealthCheckType.REVERSEDNS => hc.ReverseDnsAnalysis,
                    HealthCheckType.FCRDNS => hc.FcrDnsAnalysis,
                    HealthCheckType.CAA => hc.CAAAnalysis,
                    HealthCheckType.NS => hc.NSAnalysis,
                    HealthCheckType.DELEGATION => hc.NSAnalysis,
                    HealthCheckType.ZONETRANSFER => hc.ZoneTransferAnalysis,
                    HealthCheckType.DANE => hc.DaneAnalysis,
                    HealthCheckType.DNSBL => hc.DNSBLAnalysis,
                    HealthCheckType.DNSSEC => hc.DnsSecAnalysis,
                    HealthCheckType.AUTODISCOVER => hc.AutodiscoverAnalysis,
                    HealthCheckType.CONTACT => hc.ContactInfoAnalysis,
                    HealthCheckType.ARC => hc.ArcAnalysis,
                    HealthCheckType.DANGLINGCNAME => hc.DanglingCnameAnalysis,
                    HealthCheckType.SMTPBANNER => hc.SmtpBannerAnalysis,
                    HealthCheckType.IMAPTLS => hc.ImapTlsAnalysis,
                    HealthCheckType.POP3TLS => hc.Pop3TlsAnalysis,
                    HealthCheckType.PORTAVAILABILITY => hc.PortAvailabilityAnalysis,
                    HealthCheckType.PORTSCAN => hc.PortScanAnalysis,
                    HealthCheckType.IPNEIGHBOR => hc.IPNeighborAnalysis,
                    HealthCheckType.DNSTUNNELING => hc.DnsTunnelingAnalysis,
                    HealthCheckType.WILDCARDDNS => hc.WildcardDnsAnalysis,
                    HealthCheckType.EDNSSUPPORT => hc.EdnsSupportAnalysis,
                    _ => null
                };
                if (data != null) {
                    var desc = DomainHealthCheck.GetCheckDescription(check);
                    var header = desc != null ? $"{check} for {domain} - {desc.Summary}" : $"{check} for {domain}";
                    CliHelpers.ShowPropertiesTable(header, data, unicodeOutput);
                }
            }
            if (checkHttp) {
                CliHelpers.ShowPropertiesTable($"PLAIN HTTP for {domain}", hc.HttpAnalysis, unicodeOutput);
            }
        }
    }
}
