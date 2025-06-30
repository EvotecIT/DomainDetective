using DomainDetective;
using DnsClientX;
using Spectre.Console;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

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

    /// <summary>
    /// Application entry point.
    /// </summary>
    private static async Task<int> Main(string[] args)
    {
        var root = new RootCommand("DomainDetective CLI - HTTPS DANE queries use port 443 by default");
        var domainsArg = new Argument<string[]>("domains") { Arity = ArgumentArity.ZeroOrMore };
        var checksOption = new Option<string[]>("--checks", "Comma separated list of checks")
        {
            Arity = ArgumentArity.ZeroOrMore
        };
        var checkHttpOption = new Option<bool>("--check-http", "Perform plain HTTP check");
        var summaryOption = new Option<bool>("--summary", "Show condensed summary");
        var jsonOption = new Option<bool>("--json", "Output raw JSON");
        var subPolicyOption = new Option<bool>("--subdomain-policy", "Include DMARC sp tag in policy evaluation");
        var danePortsOption = new Option<string?>("--dane-ports", "Comma separated list of DANE ports");
        var smimeOption = new Option<FileInfo?>("--smime", "Parse S/MIME certificate file and exit");
        var certOption = new Option<FileInfo?>("--cert", "Parse general certificate file and exit");
        root.Add(domainsArg);
        root.Add(checksOption);
        root.Add(checkHttpOption);
        root.Add(summaryOption);
        root.Add(jsonOption);
        root.Add(subPolicyOption);
        root.Add(danePortsOption);
        root.Add(smimeOption);
        root.Add(certOption);

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

        var analyzeArc = new Command("AnalyzeARC", "Analyze ARC headers");
        var arcFileOpt = new Option<FileInfo?>("--file", "Header file");
        var arcHeaderOpt = new Option<string?>("--header", "Header text");
        var arcJsonOpt = new Option<bool>("--json", "Output raw JSON");
        analyzeArc.Add(arcFileOpt);
        analyzeArc.Add(arcHeaderOpt);
        analyzeArc.Add(arcJsonOpt);
        analyzeArc.SetAction(result =>
        {
            var file = result.GetValue(arcFileOpt);
            var header = result.GetValue(arcHeaderOpt);
            var json = result.GetValue(arcJsonOpt);
            AnalyzeARC(file, header, json);
        });
        root.Add(analyzeArc);

        var whoisArg = new Argument<string>("domain");
        var whoisSnap = new Option<DirectoryInfo?>("--snapshot-path", "Directory for snapshots");
        var whoisDiff = new Option<bool>("--diff", "Show changes since last snapshot");
        var whoisCmd = new Command("Whois", "Query WHOIS information")
        {
            whoisArg,
            whoisSnap,
            whoisDiff
        };
        whoisCmd.SetAction(async result =>
        {
            var domain = result.GetValue(whoisArg);
            var snap = result.GetValue(whoisSnap);
            var diff = result.GetValue(whoisDiff);
            var analysis = new WhoisAnalysis { SnapshotDirectory = snap?.FullName };
            await analysis.QueryWhoisServer(domain);
            IEnumerable<string>? changes = null;
            if (diff && snap != null)
            {
                changes = analysis.GetWhoisChanges();
            }
            if (snap != null)
            {
                analysis.SaveSnapshot();
            }
            CliHelpers.ShowPropertiesTable($"WHOIS for {domain}", analysis);
            if (changes != null && changes.Any())
            {
                AnsiConsole.MarkupLine("[yellow]Changes since last snapshot:[/]");
                foreach (var line in changes)
                {
                    Console.WriteLine(line);
                }
            }
        });
        root.Add(whoisCmd);

      
        var analyzeDnsTunnel = new Command("AnalyzeDnsTunneling", "Analyze DNS logs for tunneling patterns");
        var tunnelDomain = new Option<string>("--domain", "Domain to inspect");
        var tunnelFile = new Option<FileInfo>("--file", "Log file");
        var tunnelJson = new Option<bool>("--json", "Output raw JSON");
        analyzeDnsTunnel.Add(tunnelDomain);
        analyzeDnsTunnel.Add(tunnelFile);
        analyzeDnsTunnel.Add(tunnelJson);
        analyzeDnsTunnel.SetAction(result =>
        {
            var domain = result.GetValue(tunnelDomain);
            var file = result.GetValue(tunnelFile);
            var json = result.GetValue(tunnelJson);
            AnalyzeDnsTunneling(domain, file.FullName, json);
        });
        root.Add(analyzeDnsTunnel);

        var dnsProp = new Command("DnsPropagation", "Check DNS propagation across public resolvers");
        var propDomain = new Option<string>("--domain", "Domain to query");
        var propType = new Option<DnsRecordType>("--record-type", "DNS record type");
        var propServers = new Option<FileInfo>("--servers-file")
        {
            Description = "Servers JSON file",
            DefaultValueFactory = _ => new FileInfo("Data/DNS/PublicDNS.json")
        };
        var propJson = new Option<bool>("--json", "Output raw JSON");
        var propCompare = new Option<bool>("--compare-results", "Return aggregated comparison of results");
        dnsProp.Add(propDomain);
        dnsProp.Add(propType);
        dnsProp.Add(propServers);
        dnsProp.Add(propJson);
        dnsProp.Add(propCompare);
        dnsProp.SetAction(async result =>
        {
            var domain = result.GetValue(propDomain);
            var type = result.GetValue(propType);
            var file = result.GetValue(propServers);
            var json = result.GetValue(propJson);
            var compare = result.GetValue(propCompare);
            var analysis = new DnsPropagationAnalysis();
            analysis.LoadServers(file.FullName, clearExisting: true);
            var servers = analysis.Servers;
            var results = await analysis.QueryAsync(domain, type, servers);
            if (compare)
            {
                var groups = DnsPropagationAnalysis.CompareResults(results);
                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(groups));
                }
                else
                {
                    foreach (var kvp in groups)
                    {
                        Console.WriteLine($"{kvp.Key}: {string.Join(',', kvp.Value.Select(s => s.IPAddress))}");
                    }
                }
            }
            else
            {
                if (json)
                {
                    Console.WriteLine(JsonSerializer.Serialize(results));
                }
                else
                {
                    foreach (var r in results)
                    {
                        Console.WriteLine($"{r.Server.IPAddress} {r.Success} {string.Join(',', r.Records)}");
                    }
                }
            }
        });
      
      
        root.Add(dnsProp);
        var buildDmarc = new Command("BuildDmarcRecord", "Interactively build a DMARC record");
        buildDmarc.SetAction(_ =>
        {
            var policy = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("Select policy (p)")
                .AddChoices("none", "quarantine", "reject"));

            var subPolicy = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("Subdomain policy (sp) [inherit if blank]")
                .AddChoices("inherit", "none", "quarantine", "reject"));

            var rua = AnsiConsole.Ask<string>("Aggregate report URI (rua) [optional]", string.Empty);
            var ruf = AnsiConsole.Ask<string>("Forensic report URI (ruf) [optional]", string.Empty);
            var pct = AnsiConsole.Ask<int?>("Percentage (pct) [0-100, optional]", null);
            var adkim = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("DKIM alignment (adkim) [optional]")
                .AddChoices("default", "r", "s"));
            var aspf = AnsiConsole.Prompt(new SelectionPrompt<string>()
                .Title("SPF alignment (aspf) [optional]")
                .AddChoices("default", "r", "s"));
            var fo = AnsiConsole.Ask<string>("Failure options (fo) [optional]", string.Empty);
            var ri = AnsiConsole.Ask<int?>("Reporting interval (ri) [optional]", null);

            var parts = new List<string> { "v=DMARC1", $"p={policy}" };
            if (!string.IsNullOrWhiteSpace(rua)) parts.Add($"rua={rua}");
            if (!string.IsNullOrWhiteSpace(ruf)) parts.Add($"ruf={ruf}");
            if (pct.HasValue) parts.Add($"pct={pct.Value}");
            if (!string.IsNullOrWhiteSpace(subPolicy) && subPolicy != "inherit") parts.Add($"sp={subPolicy}");
            if (adkim != "default") parts.Add($"adkim={adkim}");
            if (aspf != "default") parts.Add($"aspf={aspf}");
            if (!string.IsNullOrWhiteSpace(fo)) parts.Add($"fo={fo}");
            if (ri.HasValue) parts.Add($"ri={ri.Value}");

            var record = string.Join("; ", parts) + ";";
            AnsiConsole.MarkupLine($"[green]{record}[/]");
        });
        root.Add(buildDmarc);


        root.SetAction(async result =>
        {
            var domains = result.GetValue(domainsArg);
            var checks = result.GetValue(checksOption) ?? Array.Empty<string>();
            var checkHttp = result.GetValue(checkHttpOption);
            var summary = result.GetValue(summaryOption);
            var json = result.GetValue(jsonOption);
            var subPolicy = result.GetValue(subPolicyOption);
            var danePortsValue = result.GetValue(danePortsOption);
            var smime = result.GetValue(smimeOption);
            var cert = result.GetValue(certOption);

            if (smime != null)
            {
                var smimeAnalysis = new SmimeCertificateAnalysis();
                smimeAnalysis.AnalyzeFile(smime.FullName);
                CliHelpers.ShowPropertiesTable($"S/MIME certificate {smime.FullName}", smimeAnalysis);
                return;
            }

            if (cert != null)
            {
                var certAnalysis = new CertificateAnalysis();
                await certAnalysis.AnalyzeCertificate(new X509Certificate2(cert.FullName));
                CliHelpers.ShowPropertiesTable($"Certificate {cert.FullName}", certAnalysis);
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
            int[]? danePorts = null;
            if (!string.IsNullOrWhiteSpace(danePortsValue)) {
                danePorts = danePortsValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Select(p => int.TryParse(p, out var val) ? val : 0)
                    .Where(p => p > 0)
                    .ToArray();
            }
            await RunChecks(domains, arr, checkHttp, json, summary, subPolicy, danePorts);
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
    /// Analyzes ARC headers and prints the results.
    /// </summary>
    private static void AnalyzeARC(FileInfo? file, string? header, bool json)
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
        var result = hc.VerifyARC(headerText);

        if (json)
        {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        }
        else
        {
            CliHelpers.ShowPropertiesTable("ARC Analysis", result);
        }
    }

    /// <summary>
    /// Analyzes DNS logs for tunneling patterns and prints the results.
    /// </summary>
    private static void AnalyzeDnsTunneling(string domain, string filePath, bool json)
    {
        if (!File.Exists(filePath))
        {
            AnsiConsole.MarkupLine($"[red]File not found: {filePath}[/]");
            return;
        }
        var lines = File.ReadAllLines(filePath);
        var hc = new DomainHealthCheck { DnsTunnelingLogs = lines };
        hc.CheckDnsTunneling(domain);
        var result = hc.DnsTunnelingAnalysis;
        if (json)
        {
            var jsonText = JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true });
            Console.WriteLine(jsonText);
        }
        else
        {
            CliHelpers.ShowPropertiesTable($"DNS Tunneling for {domain}", result);
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
        var subPolicy = AnsiConsole.Confirm("Evaluate subdomain policy?");

        await RunChecks(domains, checks, checkHttp, outputJson, summaryOnly, subPolicy, null);
        return 0;
    }

    /// <summary>
    /// Runs the selected health checks for the provided domains.
    /// </summary>
    private static async Task RunChecks(string[] domains, HealthCheckType[]? checks, bool checkHttp, bool outputJson, bool summaryOnly, bool subdomainPolicy, int[]? danePorts)
    {
        foreach (var domain in domains)
        {
            var logger = new InternalLogger();
            var hc = new DomainHealthCheck(internalLogger: logger) { Verbose = false, UseSubdomainPolicy = subdomainPolicy };
            var needsPortScan = checks?.Contains(HealthCheckType.PORTSCAN) ?? false;
            if (needsPortScan)
            {
                await AnsiConsole.Progress().StartAsync(async ctx =>
                {
                    ProgressTask? task = null;
                    void Handler(object? _, LogEventArgs e)
                    {
                        if (e.ProgressActivity == "PortScan" && e.ProgressTotalSteps.HasValue && e.ProgressCurrentSteps.HasValue)
                        {
                            task ??= ctx.AddTask($"Port scan for {domain}", maxValue: e.ProgressTotalSteps.Value);
                            task.Value = e.ProgressCurrentSteps.Value;
                        }
                    }

                    logger.OnProgressMessage += Handler;
                    try
                    {
                        await hc.Verify(domain, checks, null, null, danePorts);
                        if (checkHttp)
                        {
                            await hc.VerifyPlainHttp(domain);
                        }
                    }
                    finally
                    {
                        logger.OnProgressMessage -= Handler;
                    }
                });
            }
            else
            {
                await hc.Verify(domain, checks, null, null, danePorts);
                if (checkHttp)
                {
                    await hc.VerifyPlainHttp(domain);
                }
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
