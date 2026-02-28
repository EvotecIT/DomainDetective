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
            config.AddExample(new[] { "wizard", "--domain", "example.com" });
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

            // Time-series ingestion (store)
            config.AddCommand<DomainDetective.CLI.Commands.ImportDmarcAggregateSnapshotCommand>("ImportDmarcAggregateSnapshot")
                .WithDescription("Import DMARC aggregate (RUA) reports into a time-series store")
                .WithExample(new[] { "ImportDmarcAggregateSnapshot", "./Reports/DMARC", "--store-path", "./Store" })
                .WithExample(new[] { "ImportDmarcAggregateSnapshot", "--store-path", "./Store", "--imap-host", "imap.example.com", "--imap-user", "user@example.com", "--imap-password-env", "DMARC_IMAP_PASSWORD", "--mailbox", "INBOX", "--since-utc", "2025-01-01" });
            config.AddCommand<DomainDetective.CLI.Commands.ImportTlsRptReportSnapshotCommand>("ImportTlsRptReportSnapshot")
                .WithDescription("Import TLS-RPT JSON reports into a time-series store")
                .WithExample(new[] { "ImportTlsRptReportSnapshot", "example.com", "./Reports/TLSRPT", "--store-path", "./Store" })
                .WithExample(new[] { "ImportTlsRptReportSnapshot", "example.com", "--store-path", "./Store", "--imap-host", "imap.example.com", "--imap-user", "user@example.com", "--imap-password-env", "TLSRPT_IMAP_PASSWORD", "--mailbox", "INBOX", "--since-utc", "2025-01-01" });
            config.AddCommand<DomainDetective.CLI.Commands.ImportRegistrationSnapshotCommand>("ImportRegistrationSnapshot")
                .WithDescription("Capture WHOIS/RDAP registration snapshot into a time-series store")
                .WithExample(new[] { "ImportRegistrationSnapshot", "example.com", "--store-path", "./Store" });
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
            config.AddCommand<ValidateEmailCommand>("ValidateEmail")
                .WithDescription("Validate an email address")
                .WithExample(new[] { "ValidateEmail", "user@example.com" })
                .WithExample(new[] { "ValidateEmail", "user@example.com", "--smtp", "--catch-all" });
            config.AddCommand<ValidateEmailCommand>("email-validate")
                .WithDescription("Validate an email address (alias)")
                .WithExample(new[] { "email-validate", "user@example.com" });
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
            config.AddCommand<SpfTestHostCommand>("SpfTestHost")
                .WithDescription("Evaluate an IP/sender/HELO against SPF policy")
                .WithExample(new[] { "SpfTestHost", "example.com", "--ip", "192.0.2.10" })
                .WithExample(new[] { "SpfTestHost", "example.com", "--ip", "192.0.2.10", "--sender", "postmaster@example.com", "--json" });
            config.AddCommand<TestOpenResolverCommand>("TestOpenResolver")
                .WithDescription("Check DNS server for recursion")
                .WithExample(new[] { "TestOpenResolver", "8.8.8.8" });
            config.AddCommand<TestNtpServerCommand>("TestNtpServer")
                .WithDescription("Query NTP server for clock offset")
                .WithExample(new[] { "TestNtpServer", "--builtin", "Pool" });   

            // Reports
            config.AddCommand<DomainDetective.CLI.Commands.GenerateReportCommand>("GenerateReport")
                .WithDescription("Generate reports (HTML/Word/Markdown/etc.)")
                .WithExample(new[] { "GenerateReport", "example.com", "--format", "html" })
                .WithExample(new[] { "GenerateReport", "example.com", "--format", "word", "--store-path", "./Store" });
            config.AddCommand<DomainDetective.CLI.Commands.GenerateReportCommand>("report")
                .WithDescription("Generate reports (alias)")
                .WithExample(new[] { "report", "example.com", "--format", "html" });

            // Artifacts utilities
            config.AddCommand<DomainDetective.CLI.Commands.RunsListCommand>("RunsList")
                .WithDescription("List recent artifact runs (reads index.jsonl)")
                .WithExample(new[] { "RunsList", "--subject", "example.com" })  
                .WithExample(new[] { "RunsList", "--count", "5" });
            config.AddCommand<DomainDetective.CLI.Commands.RunsOpenCommand>("RunsOpen")
                .WithDescription("Open most recent run directory or scan.json")
                .WithExample(new[] { "RunsOpen", "--subject", "example.com" })
                .WithExample(new[] { "RunsOpen", "--dir", "/path/to/run" });

            // Certificate inventory utilities
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventorySummaryCommand>("CertificateInventorySummary")
                .WithDescription("Summarize persisted certificate inventory snapshots")
                .WithExample(new[] { "CertificateInventorySummary", "--since-utc", "2026-01-01" })
                .WithExample(new[] { "CertificateInventorySummary", "--cache-dir", "./cert-monitor", "--json" })
                .WithExample(new[] { "CertificateInventorySummary", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-summary.csv" })
                .WithExample(new[] { "CertificateInventorySummary", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-summary.csv.gz" })
                .WithExample(new[] { "CertificateInventorySummary", "--since-utc", "2026-01-01", "--ndjson-path", "./artifacts/cert-summary.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventorySummaryCommand>("cert-inventory-summary")
                .WithDescription("Summarize persisted certificate inventory snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryQueryCommand>("CertificateInventoryQuery")
                .WithDescription("Query persisted certificate inventory snapshots with filters")
                .WithExample(new[] { "CertificateInventoryQuery", "--host-contains", "api", "--service", "HTTPS" })
                .WithExample(new[] { "CertificateInventoryQuery", "--issuer-contains", "digicert", "--expiring-within-days", "30", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--client-auth-only", "--chain-incomplete-only", "--max-results", "500" })
                .WithExample(new[] { "CertificateInventoryQuery", "--invalid-only", "--reachable-only", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--root-contains", "isrg", "--service", "HTTPS" })
                .WithExample(new[] { "CertificateInventoryQuery", "--authority-family", "LetsEncrypt", "--known-root-ca-only", "--auth-profile", "ServerAuthOnly" })
                .WithExample(new[] { "CertificateInventoryQuery", "--unknown-ca-only", "--show-breakdown" })
                .WithExample(new[] { "CertificateInventoryQuery", "--latest-only", "--host-contains", "api.example.com" })
                .WithExample(new[] { "CertificateInventoryQuery", "--host-contains", "example.com", "--show-breakdown" })
                .WithExample(new[] { "CertificateInventoryQuery", "--weak-key-only", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--sha1-signature-only", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--serial-number", "00AA11BB22CC33DD44EE55FF66778899", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--root-thumbprint", "5A3F4D2C1B0099887766554433221100AABBCCDD", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--ct-template-error-contains", "CensysApiUrlTemplate", "--json" })
                .WithExample(new[] { "CertificateInventoryQuery", "--since-utc", "2026-01-01", "--latest-only", "--csv-path", "./artifacts/cert-query.csv" })
                .WithExample(new[] { "CertificateInventoryQuery", "--since-utc", "2026-01-01", "--latest-only", "--ndjson-path", "./artifacts/cert-query.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryQueryCommand>("cert-inventory-query")
                .WithDescription("Query persisted certificate inventory snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryDriftCommand>("CertificateInventoryDrift")
                .WithDescription("Analyze certificate drift and rotation across persisted snapshots")
                .WithExample(new[] { "CertificateInventoryDrift", "--since-utc", "2026-01-01", "--changed-only" })
                .WithExample(new[] { "CertificateInventoryDrift", "--max-endpoints", "500", "--json" })
                .WithExample(new[] { "CertificateInventoryDrift", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-drift.csv" })
                .WithExample(new[] { "CertificateInventoryDrift", "--since-utc", "2026-01-01", "--ndjson-path", "./artifacts/cert-drift.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryDriftCommand>("cert-inventory-drift")
                .WithDescription("Analyze certificate drift and rotation across persisted snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryDiffCommand>("CertificateInventoryDiff")
                .WithDescription("Compare two certificate inventory snapshots")
                .WithExample(new[] { "CertificateInventoryDiff", "--since-utc", "2026-01-01" })
                .WithExample(new[] { "CertificateInventoryDiff", "--previous-utc", "2026-02-01", "--current-utc", "2026-02-15", "--json" })
                .WithExample(new[] { "CertificateInventoryDiff", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-diff.csv" })
                .WithExample(new[] { "CertificateInventoryDiff", "--since-utc", "2026-01-01", "--ndjson-path", "./artifacts/cert-diff.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryDiffCommand>("cert-inventory-diff")
                .WithDescription("Compare two certificate inventory snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryRiskCommand>("CertificateInventoryRisk")
                .WithDescription("Assess certificate risk posture across persisted snapshots")
                .WithExample(new[] { "CertificateInventoryRisk", "--since-utc", "2026-01-01" })
                .WithExample(new[] { "CertificateInventoryRisk", "--expiring-within-days", "45", "--critical-expiring-within-days", "10", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--issuer-contains", "digicert", "--minimum-severity", "Medium", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--authority-family", "LetsEncrypt", "--root-authority-family", "LetsEncrypt", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--ct-source-contains", "crt.sh", "--chain-source-contains", "tls-handshake", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--ct-missing-only", "--chain-incomplete-only", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--unreachable-only", "--hostname-mismatch-only", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--self-signed-only", "--weak-key-only", "--sha1-signature-only", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--expired-only", "--currently-invalid-only", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--days-to-expire-min", "0", "--days-to-expire-max", "14", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--score-min", "60", "--score-max", "100", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reason-count-min", "2", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reuse-endpoint-min", "5", "--reuse-endpoint-max", "25", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reuse-cross-service-only", "--minimum-severity", "Medium", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reuse-service-min", "2", "--reuse-port-min", "2", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reuse-cross-port-only", "--reuse-endpoint-min", "3", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--risk-profile", "Renewal14d", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reason-any", "CertificateExpired", "--reason-any", "WeakKey", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--reason-all", "CertificateExpired", "--reason-all", "CertificateValidationFailed", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--issuer-any", "digicert", "--issuer-any", "isrg", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--issuer-all", "contoso", "--issuer-all", "root", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--root-issuer-contains", "ISRG Root", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--root-issuer-any", "Global Root", "--root-issuer-any", "ISRG Root", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--chain-length-min", "2", "--intermediate-count-max", "1", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--unknown-ca-only", "--unknown-root-ca-only", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--host-contains", "api.example.com", "--service", "HTTPS", "--port", "443", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--thumbprint", "AA11BB22CC33DD44EE55FF6677889900AABBCCDD", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--root-thumbprint", "5A3F4D2C1B0099887766554433221100AABBCCDD", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--serial-number", "00AA11BB22CC33DD44EE55FF66778899", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--auth-profile", "ServerAuthOnly", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--client-auth-only", "--minimum-severity", "High", "--json" })
                .WithExample(new[] { "CertificateInventoryRisk", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-risk.csv" })
                .WithExample(new[] { "CertificateInventoryRisk", "--since-utc", "2026-01-01", "--ndjson-path", "./artifacts/cert-risk.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryRiskCommand>("cert-inventory-risk")
                .WithDescription("Assess certificate risk posture across persisted snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryPolicyCommand>("CertificateInventoryPolicy")
                .WithDescription("Evaluate certificate inventory against baseline policy profiles")
                .WithExample(new[] { "CertificateInventoryPolicy", "--since-utc", "2026-01-01" })
                .WithExample(new[] { "CertificateInventoryPolicy", "--baseline-profile", "Strict", "--json" })
                .WithExample(new[] { "CertificateInventoryPolicy", "--baseline-profile", "Legacy", "--include-compliant", "--max-endpoints", "500" })
                .WithExample(new[] { "CertificateInventoryPolicy", "--baseline-profile", "Balanced", "--csv-path", "./artifacts/policy.csv" })
                .WithExample(new[] { "CertificateInventoryPolicy", "--baseline-profile", "Balanced", "--policy-overrides-path", "./policy-overrides.json", "--json" })
                .WithExample(new[] { "CertificateInventoryPolicy", "--baseline-profile", "Balanced", "--ndjson-path", "./artifacts/policy.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryPolicyCommand>("cert-inventory-policy")
                .WithDescription("Evaluate certificate inventory against baseline policy profiles (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryPolicyDriftCommand>("CertificateInventoryPolicyDrift")
                .WithDescription("Compare policy drift between two certificate inventory snapshots")
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--changed-only" })
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--baseline-profile", "Strict", "--since-utc", "2026-01-01", "--json" })
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--previous-utc", "2026-02-01", "--current-utc", "2026-02-15", "--changed-only" })
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--baseline-profile", "Balanced", "--csv-path", "./artifacts/policy-drift.csv" })
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--baseline-profile", "Balanced", "--policy-overrides-path", "./policy-overrides.json", "--json" })
                .WithExample(new[] { "CertificateInventoryPolicyDrift", "--baseline-profile", "Balanced", "--ndjson-path", "./artifacts/policy-drift.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryPolicyDriftCommand>("cert-inventory-policy-drift")
                .WithDescription("Compare policy drift between two certificate inventory snapshots (alias)");

            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryReuseCommand>("CertificateInventoryReuse")
                .WithDescription("Map certificate reuse and endpoint assignment across persisted snapshots")
                .WithExample(new[] { "CertificateInventoryReuse", "--since-utc", "2026-01-01" })
                .WithExample(new[] { "CertificateInventoryReuse", "--include-singletons", "--max-certificates", "500", "--json" })
                .WithExample(new[] { "CertificateInventoryReuse", "--since-utc", "2026-01-01", "--csv-path", "./artifacts/cert-reuse.csv" })
                .WithExample(new[] { "CertificateInventoryReuse", "--since-utc", "2026-01-01", "--ndjson-path", "./artifacts/cert-reuse.ndjson" });
            config.AddCommand<DomainDetective.CLI.Commands.CertificateInventoryReuseCommand>("cert-inventory-reuse")
                .WithDescription("Map certificate reuse and endpoint assignment across persisted snapshots (alias)");
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
