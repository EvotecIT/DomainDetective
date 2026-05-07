using DomainDetective;
using DomainDetective.Helpers;
using DnsClientX;
using Spectre.Console;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

namespace DomainDetective.CLI;

internal static class WizardMode {
    internal static async Task<int> RunInteractiveWizard(CancellationToken cancellationToken) {
        // Don't clear console to preserve output
        Console.OutputEncoding = System.Text.Encoding.UTF8;
        
        AnsiConsole.WriteLine();
        AnsiConsole.Write(
            new Panel(
                new FigletText("DomainDetective")
                    .Color(Color.Green))
            .Header(new PanelHeader("[yellow]Interactive Domain Analysis Tool[/]"))
            .Border(BoxBorder.Rounded)
            .BorderColor(Color.Blue)
            .Expand());
        AnsiConsole.WriteLine();

        while (true) {
            var mainChoice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[green]What would you like to do?[/]")
                    .AddChoices(new[] {
                        "🔍 Quick Domain Check",
                        "🔬 Advanced Domain Analysis",
                        "📊 Custom Test Selection",
                        "📧 Email Header Analysis",
                        "🌐 WHOIS Lookup",
                        "🔒 Certificate Analysis",
                        "🚀 DNS Propagation Check",
                        "📝 Build DMARC Record",
                        "❌ Exit"
                    }));

            if (mainChoice.Contains("Exit")) {
                AnsiConsole.Write(
                    new Panel("[yellow]👋 Thank you for using DomainDetective![/]\n[dim]Stay secure![/]")
                        .Border(BoxBorder.Rounded)
                        .BorderColor(Color.Yellow));
                return 0;
            }

            try {
                var result = mainChoice switch {
                    var s when s.Contains("Quick Domain Check") => await RunQuickCheck(cancellationToken),
                    var s when s.Contains("Advanced Domain Analysis") => await RunAdvancedAnalysis(cancellationToken),
                    var s when s.Contains("Custom Test Selection") => await RunCustomTests(cancellationToken),
                    var s when s.Contains("Email Header Analysis") => await RunEmailHeaderAnalysis(cancellationToken),
                    var s when s.Contains("WHOIS Lookup") => await RunWhoisLookup(cancellationToken),
                    var s when s.Contains("Certificate Analysis") => await RunCertificateAnalysis(cancellationToken),
                    var s when s.Contains("DNS Propagation Check") => await RunDnsPropagation(cancellationToken),
                    var s when s.Contains("Build DMARC Record") => await RunDmarcBuilder(cancellationToken),
                    _ => 0
                };

                if (result != 0) {
                    AnsiConsole.MarkupLine($"[red]Operation failed with code {result}[/]");
                }
            } catch (OperationCanceledException) {
                AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Error: {ex.Message}[/]");
            }

            AnsiConsole.WriteLine();
            
            var continueChoice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[green]What would you like to do next?[/]")
                    .AddChoices(new[] {
                        "🔄 Continue with another operation",
                        "🚪 Exit application"
                    }));
            
            if (continueChoice.Contains("Exit")) {
                break;
            }
            AnsiConsole.WriteLine();
        }

        return 0;
    }

    private static async Task<int> RunQuickCheck(CancellationToken cancellationToken) {
        var domain = PromptForDomain();
        if (string.IsNullOrWhiteSpace(domain)) return 1;

        var outputFormat = PromptForOutputFormat();
        
        AnsiConsole.WriteLine();
        AnsiConsole.Write(
            new Panel($"[green]🎯 Starting Quick Check for:[/] [yellow bold]{domain}[/]")
                .Border(BoxBorder.Rounded)
                .BorderColor(Color.Green));
        AnsiConsole.WriteLine();

        var essentialChecks = new[] {
            HealthCheckType.MX,
            HealthCheckType.SPF,
            HealthCheckType.DMARC,
            HealthCheckType.DKIM,
            HealthCheckType.NS,
            HealthCheckType.CAA,
            HealthCheckType.DNSSEC
        };

        await RunAndDisplayResults(new[] { domain }, essentialChecks, outputFormat, false, false, cancellationToken);
        return 0;
    }

    private static async Task<int> RunAdvancedAnalysis(CancellationToken cancellationToken) {
        var domains = PromptForDomains();
        if (domains.Length == 0) return 1;

        var includeOptions = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select additional options:")
                .NotRequired()
                .PageSize(10)
                .AddChoices(new[] {
                    "🌐 Check HTTP/HTTPS",
                    "⚠️ Check for subdomain takeover",
                    "📮 Show Autodiscover endpoints",
                    "📋 Evaluate subdomain policy",
                    "🔍 Scan common ports",
                    "✅ Check certificate revocation"
                }));

        var outputFormat = PromptForOutputFormat();
        
        var checkHttp = includeOptions.Any(o => o.Contains("HTTP"));
        var checkTakeover = includeOptions.Any(o => o.Contains("takeover"));
        var autodiscoverEndpoints = includeOptions.Any(o => o.Contains("Autodiscover"));
        var subdomainPolicy = includeOptions.Any(o => o.Contains("subdomain policy"));
        var portScan = includeOptions.Any(o => o.Contains("ports"));
        var skipRevocation = !includeOptions.Any(o => o.Contains("revocation"));

        var checks = Enum.GetValues<HealthCheckType>();
        
        if (portScan) {
            checks = checks.Append(HealthCheckType.PORTSCAN).ToArray();
        }

        await RunAndDisplayResults(domains, checks, outputFormat, checkHttp, checkTakeover, cancellationToken,
            autodiscoverEndpoints: autodiscoverEndpoints,
            subdomainPolicy: subdomainPolicy,
            skipRevocation: skipRevocation);
        
        return 0;
    }

    private static async Task<int> RunCustomTests(CancellationToken cancellationToken) {
        var domains = PromptForDomains();
        if (domains.Length == 0) return 1;

        var categories = new Dictionary<string, HealthCheckType[]> {
            ["📧 Email Security (SPF, DKIM, DMARC, MX)"] = new[] { 
                HealthCheckType.SPF, HealthCheckType.DKIM, HealthCheckType.DMARC, HealthCheckType.MX 
            },
            ["🔒 Security (CAA, DNSSEC, DANE)"] = new[] { 
                HealthCheckType.CAA, HealthCheckType.DNSSEC, HealthCheckType.DANE 
            },
            ["🌐 DNS Health (NS, Delegation, Zone Transfer)"] = new[] { 
                HealthCheckType.NS, HealthCheckType.DELEGATION, HealthCheckType.ZONETRANSFER 
            },
            ["🚨 Reputation (DNSBL, Reverse DNS)"] = new[] { 
                HealthCheckType.DNSBL, HealthCheckType.REVERSEDNS, HealthCheckType.FCRDNS 
            },
            ["📡 Connectivity (Port Scan, SMTP Banner, IMAP/POP3)"] = new[] { 
                HealthCheckType.PORTSCAN, HealthCheckType.SMTPBANNER, HealthCheckType.IMAPTLS, HealthCheckType.POP3TLS 
            },
            ["🔍 Advanced (Wildcard DNS, DNS Tunneling, IP Neighbors)"] = new[] { 
                HealthCheckType.WILDCARDDNS, HealthCheckType.DNSTUNNELING, HealthCheckType.IPNEIGHBOR 
            },
            ["⚙️ Other (Autodiscover, Contact Info, Dangling CNAME)"] = new[] { 
                HealthCheckType.AUTODISCOVER, HealthCheckType.CONTACT, HealthCheckType.DANGLINGCNAME 
            }
        };

        var selectedCategories = AnsiConsole.Prompt(
            new MultiSelectionPrompt<string>()
                .Title("Select test categories:")
                .Required()
                .PageSize(10)
                .AddChoices(categories.Keys));

        var checks = selectedCategories
            .SelectMany(cat => categories[cat])
            .Distinct()
            .ToArray();

        var outputFormat = PromptForOutputFormat();
        
        await RunAndDisplayResults(domains, checks, outputFormat, false, false, cancellationToken);
        return 0;
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    private static async Task<int> RunEmailHeaderAnalysis(CancellationToken cancellationToken) {
        AnsiConsole.MarkupLine("[green]Email Header Analysis[/]");
        
        var inputMethod = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("How would you like to provide the email headers?")
                .AddChoices(new[] {
                    "Paste headers directly",
                    "Load from file"
                }));

        string? headerText = null;
        
        if (inputMethod == "Paste headers directly") {
            AnsiConsole.MarkupLine("[dim]Paste your email headers below (press Ctrl+D or type 'END' on a new line when done):[/]");
            var lines = new List<string>();
            string? line;
            while ((line = Console.ReadLine()) != null && line != "END") {
                lines.Add(line);
            }
            headerText = string.Join("\n", lines);
        } else {
            var filePath = AnsiConsole.Ask<string>("Enter file path:");
            if (File.Exists(filePath)) {
                headerText = await File.ReadAllTextAsync(filePath, cancellationToken);
            } else {
                AnsiConsole.MarkupLine("[red]File not found![/]");
                return 1;
            }
        }

        if (string.IsNullOrWhiteSpace(headerText)) {
            AnsiConsole.MarkupLine("[red]No header text provided.[/]");
            return 1;
        }

        var hc = new DomainHealthCheck();
        var result = hc.CheckMessageHeaders(headerText);
        
        var outputFormat = PromptForOutputFormat();
        
        if (outputFormat == OutputFormat.Json) {
            var json = JsonSerializer.Serialize(result, DomainDetective.Helpers.JsonOptions.Default);
            Console.WriteLine(json);
        } else if (outputFormat == OutputFormat.Table) {
            DisplayResultsAsTable("Email Header Analysis", result);
        } else {
            CliHelpers.ShowPropertiesTable("Email Header Analysis", result, false);
        }
        
        return 0;
    }

    private static async Task<int> RunWhoisLookup(CancellationToken cancellationToken) {
        var domain = PromptForDomain();
        if (string.IsNullOrWhiteSpace(domain)) return 1;

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Star)
            .StartAsync($"Querying WHOIS for {domain}...", async ctx => {
                var whois = new WhoisAnalysis();
                await whois.QueryWhoisServer(domain, cancellationToken);
                CliHelpers.ShowPropertiesTable($"WHOIS Data for {domain}", whois, false);
            });

        return 0;
    }

    private static async Task<int> RunCertificateAnalysis(CancellationToken cancellationToken) {
        var inputMethod = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Certificate source:")
                .AddChoices(new[] {
                    "Analyze domain's HTTPS certificate",
                    "Analyze certificate file"
                }));

        if (inputMethod.Contains("domain")) {
            var domain = PromptForDomain();
            if (string.IsNullOrWhiteSpace(domain)) return 1;

            var certAnalysis = await CertificateAnalysis.CheckWebsiteCertificate($"https://{domain}", 443, cancellationToken);
            CliHelpers.ShowPropertiesTable($"Certificate for {domain}", certAnalysis, false);
        } else {
            var filePath = AnsiConsole.Ask<string>("Enter certificate file path:");
            if (!File.Exists(filePath)) {
                AnsiConsole.MarkupLine("[red]File not found![/]");
                return 1;
            }
            
            var cert = CertificateLoaderCompat.LoadCertificateFromFile(filePath);
            var certAnalysis = new CertificateAnalysis();
            await certAnalysis.AnalyzeCertificate(cert);
            CliHelpers.ShowPropertiesTable($"Certificate from {filePath}", certAnalysis, false);
        }

        return 0;
    }

    private static async Task<int> RunDnsPropagation(CancellationToken cancellationToken) {
        var domain = PromptForDomain();
        if (string.IsNullOrWhiteSpace(domain)) return 1;

        var recordType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select DNS record type:")
                .AddChoices(new[] { "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA" }));

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Star)
            .StartAsync($"Checking DNS propagation for {domain} ({recordType})...", async ctx => {
                var propagation = new DnsPropagationAnalysis();
                propagation.LoadBuiltinServers();
                var servers = propagation.Servers.OrderBy(_ => Guid.NewGuid()).Take(10).ToList();
                
                DnsRecordType dnsRecordType = recordType switch {
                    "A" => DnsRecordType.A,
                    "AAAA" => DnsRecordType.AAAA,
                    "MX" => DnsRecordType.MX,
                    "TXT" => DnsRecordType.TXT,
                    "NS" => DnsRecordType.NS,
                    "CNAME" => DnsRecordType.CNAME,
                    "SOA" => DnsRecordType.SOA,
                    _ => DnsRecordType.A
                };
                
                var results = await propagation.QueryAsync(domain, dnsRecordType, servers, cancellationToken);
                
                var table = new Table();
                table.AddColumn("Resolver");
                table.AddColumn("Location");
                table.AddColumn("Result");
                table.AddColumn("Response Time");
                
                foreach (var result in results) {
                    var resultColor = result.Success ? "green" : "red";
                    table.AddRow(
                        result.Server?.HostName ?? "Unknown",
                        result.Server?.Location?.ToString() ?? "Unknown",
                        $"[{resultColor}]{(result.Success ? string.Join(", ", result.Records ?? Array.Empty<string>()) : result.Error ?? "Failed")}[/]",
                        $"{result.Duration.TotalMilliseconds:F0}ms"
                    );
                }
                
                AnsiConsole.Write(table);
            });

        return 0;
    }

    private static Task<int> RunDmarcBuilder(CancellationToken cancellationToken) {
        AnsiConsole.MarkupLine("[green]Interactive DMARC Record Builder[/]");
        
        var policy = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select DMARC policy:")
                .AddChoices(new[] { "none", "quarantine", "reject" }));

        var percentage = AnsiConsole.Ask("Percentage of messages to apply policy to:", 100);
        var rua = AnsiConsole.Ask<string?>("Aggregate report email (rua):", null);
        var ruf = AnsiConsole.Ask<string?>("Forensic report email (ruf):", null);
        
        var alignment = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("SPF alignment mode:")
                .AddChoices(new[] { "relaxed", "strict" }));

        var dkimAlignment = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("DKIM alignment mode:")
                .AddChoices(new[] { "relaxed", "strict" }));

        var record = $"v=DMARC1; p={policy}; pct={percentage}";
        if (!string.IsNullOrEmpty(rua)) record += $"; rua=mailto:{rua}";
        if (!string.IsNullOrEmpty(ruf)) record += $"; ruf=mailto:{ruf}";
        record += $"; aspf={alignment[0]}; adkim={dkimAlignment[0]}";

        var panel = new Panel(record) {
            Header = new PanelHeader("Generated DMARC Record"),
            Border = BoxBorder.Rounded,
            Expand = true
        };
        AnsiConsole.Write(panel);
        
        AnsiConsole.MarkupLine($"[dim]Add this TXT record to: _dmarc.yourdomain.com[/]");
        
        return Task.FromResult(0);
    }

    private static string PromptForDomain() {
        return AnsiConsole.Prompt(
            new TextPrompt<string>("Enter domain to analyze:")
                .Validate(input => string.IsNullOrWhiteSpace(input)
                    ? ValidationResult.Error("[red]Domain is required[/]")
                    : ValidationResult.Success()));
    }

    private static string[] PromptForDomains() {
        var input = AnsiConsole.Prompt(
            new TextPrompt<string>("Enter domain(s) [comma separated]:")
                .Validate(input => string.IsNullOrWhiteSpace(input)
                    ? ValidationResult.Error("[red]At least one domain is required[/]")
                    : ValidationResult.Success()));
        
        return input.Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => CliHelpers.ToAscii(d))
            .ToArray();
    }

    private enum OutputFormat {
        Console,
        Table,
        Json,
        Html
    }

    private static OutputFormat PromptForOutputFormat() {
        var format = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select output format:")
                .AddChoices(new[] {
                    "📺 Console (Default)",
                    "📊 Table View",
                    "📋 JSON",
                    "🌐 HTML Report"
                }));

        return format switch {
            var s when s.Contains("JSON") => OutputFormat.Json,
            var s when s.Contains("Table") => OutputFormat.Table,
            var s when s.Contains("HTML") => OutputFormat.Html,
            _ => OutputFormat.Console
        };
    }

    private static async Task RunAndDisplayResults(
        string[] domains,
        HealthCheckType[] checks,
        OutputFormat outputFormat,
        bool checkHttp,
        bool checkTakeover,
        CancellationToken cancellationToken,
        bool autodiscoverEndpoints = false,
        bool subdomainPolicy = false,
        bool skipRevocation = false,
        int[]? danePorts = null,
        PortScanProfileDefinition.PortScanProfile[]? portProfiles = null) {
        
        foreach (var domain in domains) {
            var hc = new DomainHealthCheck {
                UseSubdomainPolicy = subdomainPolicy,
                Progress = false, // Disable internal progress
                Verbose = false   // Disable verbose logging
            };
            
            if (skipRevocation) {
                hc.CertificateAnalysis.SkipRevocation = true;
            }

            // Use Progress instead of Status for better feedback
            await AnsiConsole.Progress()
                .AutoClear(false)
                .HideCompleted(false)
                .Columns(new ProgressColumn[] {
                    new TaskDescriptionColumn(),
                    new ProgressBarColumn(),
                    new PercentageColumn(),
                    new RemainingTimeColumn(),
                    new SpinnerColumn()
                })
                .StartAsync(async ctx => {
                    var mainTask = ctx.AddTask($"[green]Analyzing {domain}[/]", maxValue: checks.Length + (checkHttp ? 1 : 0) + (checkTakeover ? 1 : 0));
                    
                    // Run each check individually with progress updates
                    foreach (var check in checks) {
                        mainTask.Description = $"[green]{domain}[/]: [yellow]{check}[/]";
                        await hc.Verify(domain, new[] { check }, null, null, danePorts, portProfiles, cancellationToken);
                        mainTask.Increment(1);
                    }
                    
                    if (checkHttp) {
                        mainTask.Description = $"[green]{domain}[/]: [yellow]HTTP Check[/]";
                        await hc.VerifyPlainHttp(domain, cancellationToken);
                        mainTask.Increment(1);
                    }
                    
                    if (checkTakeover) {
                        mainTask.Description = $"[green]{domain}[/]: [yellow]Subdomain Takeover[/]";
                        await hc.VerifyTakeoverCname(domain, cancellationToken);
                        mainTask.Increment(1);
                    }
                    
                    mainTask.Description = $"[green]{domain}[/]: [bold green]Complete![/]";
                });

            if (outputFormat == OutputFormat.Json) {
                Console.WriteLine(hc.ToJson());
                if (AnsiConsole.Confirm("Export results to file?")) {
                    var fileName = AnsiConsole.Ask("Enter filename:", $"{domain}_results.json");
                    OutputFormatters.ExportToJson(hc, fileName);
                }
            } else if (outputFormat == OutputFormat.Table) {
                DisplayResultsAsTable($"Results for {domain}", hc, checks, checkHttp, checkTakeover, autodiscoverEndpoints);
            } else if (outputFormat == OutputFormat.Html) {
                var fileName = AnsiConsole.Ask("Enter HTML filename:", $"{domain}_report.html");
                OutputFormatters.ExportToHtml(domain, hc, fileName);
                if (AnsiConsole.Confirm("Open in browser?")) {
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo {
                        FileName = fileName,
                        UseShellExecute = true
                    });
                }
            } else {
                DisplayResultsAsConsole(domain, hc, checks, checkHttp, checkTakeover, autodiscoverEndpoints);
                if (AnsiConsole.Confirm("Export results?")) {
                    var format = AnsiConsole.Prompt(
                        new SelectionPrompt<string>()
                            .Title("Export format:")
                            .AddChoices(new[] { "JSON", "HTML" }));
                    
                    if (format == "JSON") {
                        var fileName = AnsiConsole.Ask("Enter filename:", $"{domain}_results.json");
                        OutputFormatters.ExportToJson(hc, fileName);
                    } else {
                        var fileName = AnsiConsole.Ask("Enter filename:", $"{domain}_report.html");
                        OutputFormatters.ExportToHtml(domain, hc, fileName);
                    }
                }
            }
        }
    }

    private static void DisplayResultsAsTable(string title, object data) {
        var table = new Table() {
            Title = new TableTitle(title),
            Border = TableBorder.Rounded
        };
        
        table.AddColumn("Property");
        table.AddColumn("Value");
        
        var properties = data.GetType().GetProperties();
        foreach (var prop in properties) {
            var value = prop.GetValue(data);
            table.AddRow(prop.Name, value?.ToString() ?? "null");
        }
        
        AnsiConsole.Write(table);
    }

    private static void DisplayResultsAsTable(
        string title,
        DomainHealthCheck hc,
        HealthCheckType[] checks,
        bool checkHttp,
        bool checkTakeover,
        bool autodiscoverEndpoints) {
        
        OutputFormatters.FormatAsRichTable(title.Replace("Results for ", ""), hc, checks);
        
        if (AnsiConsole.Confirm("Show detailed summary cards?")) {
            OutputFormatters.FormatAsSummaryCards(title.Replace("Results for ", ""), hc);
        }
    }

    private static void DisplayResultsAsConsole(
        string domain,
        DomainHealthCheck hc,
        HealthCheckType[] checks,
        bool checkHttp,
        bool checkTakeover,
        bool autodiscoverEndpoints) {
        
        foreach (var check in checks) {
            var data = GetCheckData(hc, check);
            if (data != null) {
                var desc = DomainHealthCheck.GetCheckDescription(check);
                var header = desc != null ? $"{check} for {domain} - {desc.Summary}" : $"{check} for {domain}";
                CliHelpers.ShowPropertiesTable(header, data, false);
                
                if (check == HealthCheckType.AUTODISCOVER && autodiscoverEndpoints && hc.AutodiscoverHttpAnalysis?.Endpoints != null) {
                    CliHelpers.ShowPropertiesTable($"AUTODISCOVER ENDPOINTS for {domain}", hc.AutodiscoverHttpAnalysis.Endpoints, false);
                }
            }
        }
        
        if (checkHttp && hc.HttpAnalysis != null) {
            CliHelpers.ShowPropertiesTable($"PLAIN HTTP for {domain}", hc.HttpAnalysis, false);
        }
        
        if (checkTakeover && hc.TakeoverCnameAnalysis != null) {
            CliHelpers.ShowPropertiesTable($"TAKEOVER for {domain}", hc.TakeoverCnameAnalysis, false);
        }
    }

    private static object? GetCheckData(DomainHealthCheck hc, HealthCheckType check) {
        return check switch {
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
            HealthCheckType.DNSAMPLIFICATION => hc.DnsAmplificationAnalysis,
            HealthCheckType.DNSOVERTLS => hc.DnsOverTlsAnalysis,
            HealthCheckType.AGENTREADINESS => hc.AgentReadinessAnalysis,
            HealthCheckType.SITEMAP => hc.SitemapAnalysis,
            _ => null
        };
    }

    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize")]
    private static Panel CreateCheckPanel(string title, object data) {
        var content = JsonSerializer.Serialize(data, DomainDetective.Helpers.JsonOptions.Default);
        return new Panel(content) {
            Header = new PanelHeader(title),
            Border = BoxBorder.Rounded
        };
    }
}
