using DnsClientX;
using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective.CLI.Commands;

/// <summary>
/// Settings for <see cref="CertificateInventoryCaptureCommand"/>.
/// </summary>
internal sealed class CertificateInventoryCaptureSettings : CommandSettings {
    [Description("Domains to discover/probe.")]
    [CommandArgument(0, "[domains]")]
    public string[] Domains { get; set; } = Array.Empty<string>();

    [Description("Optional text file containing domains/endpoints (one per line).")]
    [CommandOption("--domains-file <PATH>")]
    public string? DomainsFile { get; set; }

    [Description("Certificate monitor cache directory (defaults to system temp path).")]
    [CommandOption("--cache-dir <PATH>")]
    public string? CacheDirectory { get; set; }

    [Description("DNS endpoint used for MX discovery.")]
    [CommandOption("--dns-endpoint <ENDPOINT>")]
    public DnsEndpoint DnsEndpoint { get; set; } = DnsEndpoint.System;

    [Description("Do not probe apex domains over HTTPS.")]
    [CommandOption("--no-apex-https")]
    public bool NoApexHttps { get; set; }

    [Description("Do not probe www.<domain> over HTTPS.")]
    [CommandOption("--no-www-https")]
    public bool NoWwwHttps { get; set; }

    [Description("Enable HTTPS probing for discovered MX hosts.")]
    [CommandOption("--include-mx-https")]
    public bool IncludeMxHttps { get; set; }

    [Description("Disable MX discovery from DNS.")]
    [CommandOption("--disable-mx-discovery")]
    public bool DisableMxDiscovery { get; set; }

    [Description("Disable SMTP STARTTLS probing on port 25.")]
    [CommandOption("--disable-smtp-starttls")]
    public bool DisableSmtpStartTls { get; set; }

    [Description("Disable SMTP STARTTLS probing on submission port 587.")]
    [CommandOption("--disable-submission-starttls")]
    public bool DisableSubmissionStartTls { get; set; }

    [Description("Enable IMAP TLS probing on port 993.")]
    [CommandOption("--include-imap-tls")]
    public bool IncludeImapTls { get; set; }

    [Description("Enable POP3 TLS probing on port 995.")]
    [CommandOption("--include-pop3-tls")]
    public bool IncludePop3Tls { get; set; }

    [Description("Additional endpoint(s) to probe. Repeat option for multiple values.")]
    [CommandOption("--endpoint <ENDPOINT>")]
    public string[] AdditionalEndpoints { get; set; } = Array.Empty<string>();

    [Description("Maximum MX hosts retained per domain (0 means unlimited).")]
    [CommandOption("--mx-max-hosts <N>")]
    [DefaultValue(50)]
    public int MaxMxHostsPerDomain { get; set; } = 50;

    [Description("Maximum concurrent probe operations.")]
    [CommandOption("--max-parallelism <N>")]
    [DefaultValue(16)]
    public int MaxParallelism { get; set; } = 16;

    [Description("Maximum concurrent domain discovery operations.")]
    [CommandOption("--discovery-parallelism <N>")]
    [DefaultValue(20)]
    public int DiscoveryParallelism { get; set; } = 20;

    [Description("Mail TLS timeout in seconds.")]
    [CommandOption("--mail-timeout-seconds <SECONDS>")]
    [DefaultValue(15)]
    public int MailTimeoutSeconds { get; set; } = 15;

    [Description("Skip revocation checks for HTTPS probes.")]
    [CommandOption("--skip-revocation")]
    public bool SkipRevocation { get; set; }

    [Description("CT enrichment profile: Default, Disabled, Public, Extended.")]
    [CommandOption("--ct-profile <PROFILE>")]
    public CertificateCtEnrichmentProfile CtProfile { get; set; } = CertificateCtEnrichmentProfile.Default;

    [Description("Disable default crt.sh template during CT lookups.")]
    [CommandOption("--disable-default-ct-template")]
    public bool DisableDefaultCtTemplate { get; set; }

    [Description("Additional CT API template(s). Repeat option for multiple values.")]
    [CommandOption("--ct-template <TEMPLATE>")]
    public string[] CtApiTemplates { get; set; } = Array.Empty<string>();

    [Description("Enable Censys CT source.")]
    [CommandOption("--enable-censys-ct")]
    public bool EnableCensysCtSource { get; set; }

    [Description("Censys API identifier.")]
    [CommandOption("--censys-api-id <ID>")]
    public string? CensysApiId { get; set; }

    [Description("Censys API secret.")]
    [CommandOption("--censys-api-secret <SECRET>")]
    public string? CensysApiSecret { get; set; }

    [Description("Environment variable containing Censys API secret.")]
    [CommandOption("--censys-api-secret-env <ENV>")]
    public string? CensysApiSecretEnv { get; set; }

    [Description("Censys CT URL template containing {0} fingerprint placeholder.")]
    [CommandOption("--censys-ct-url-template <TEMPLATE>")]
    public string? CensysCtApiUrlTemplate { get; set; }

    [Description("Enable Shodan CT source.")]
    [CommandOption("--enable-shodan-ct")]
    public bool EnableShodanCtSource { get; set; }

    [Description("Shodan API key.")]
    [CommandOption("--shodan-api-key <KEY>")]
    public string? ShodanApiKey { get; set; }

    [Description("Environment variable containing Shodan API key.")]
    [CommandOption("--shodan-api-key-env <ENV>")]
    public string? ShodanApiKeyEnv { get; set; }

    [Description("Shodan CT URL template containing {0} fingerprint and {1} API key placeholders.")]
    [CommandOption("--shodan-ct-url-template <TEMPLATE>")]
    public string? ShodanCtApiUrlTemplate { get; set; }

    [Description("Do not persist snapshot file; only print output.")]
    [CommandOption("--no-persist")]
    public bool NoPersist { get; set; }

    [Description("Output JSON instead of tables.")]
    [CommandOption("--json")]
    public bool Json { get; set; }

    [Description("Show discovered/probed endpoint lists.")]
    [CommandOption("--show-endpoints")]
    public bool ShowEndpoints { get; set; }

    [Description("Optional CSV output path for captured entries.")]
    [CommandOption("--csv-path <PATH>")]
    public string? CsvPath { get; set; }

    [Description("Optional NDJSON output path for captured entries.")]
    [CommandOption("--ndjson-path <PATH>")]
    public string? NdjsonPath { get; set; }
}

/// <summary>
/// Captures one certificate inventory snapshot from domains and discovered service endpoints.
/// </summary>
internal sealed class CertificateInventoryCaptureCommand : AsyncCommand<CertificateInventoryCaptureSettings> {
    [RequiresUnreferencedCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    [RequiresDynamicCode("Calls System.Text.Json.JsonSerializer.Serialize<TValue>(TValue, JsonSerializerOptions)")]
    public override async Task<int> ExecuteAsync(CommandContext context, CertificateInventoryCaptureSettings settings) {
        if (settings == null) {
            throw new ArgumentNullException(nameof(settings));
        }
        if (settings.MaxMxHostsPerDomain < 0) {
            AnsiConsole.MarkupLine("[red]--mx-max-hosts must be 0 or greater.[/]");
            return 1;
        }
        if (settings.MaxParallelism < 1) {
            AnsiConsole.MarkupLine("[red]--max-parallelism must be 1 or greater.[/]");
            return 1;
        }
        if (settings.DiscoveryParallelism < 1) {
            AnsiConsole.MarkupLine("[red]--discovery-parallelism must be 1 or greater.[/]");
            return 1;
        }
        if (settings.MailTimeoutSeconds < 1 || settings.MailTimeoutSeconds > 300) {
            AnsiConsole.MarkupLine("[red]--mail-timeout-seconds must be between 1 and 300.[/]");
            return 1;
        }
        var censysSecret = ResolveSecret(settings.CensysApiSecret, settings.CensysApiSecretEnv);
        var shodanApiKey = ResolveSecret(settings.ShodanApiKey, settings.ShodanApiKeyEnv);

        var domains = new List<string>();
        if (settings.Domains != null && settings.Domains.Length > 0) {
            domains.AddRange(settings.Domains.Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d.Trim()));
        }
        if (!string.IsNullOrWhiteSpace(settings.DomainsFile)) {
            try {
                var path = Path.GetFullPath(settings.DomainsFile!);
                if (!File.Exists(path)) {
                    AnsiConsole.MarkupLine($"[red]--domains-file not found:[/] {settings.DomainsFile}");
                    return 1;
                }
                foreach (var line in File.ReadAllLines(path)) {
                    var trimmed = line?.Trim() ?? string.Empty;
                    if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#", StringComparison.Ordinal)) {
                        continue;
                    }
                    domains.Add(trimmed);
                }
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to read --domains-file:[/] {ex.Message}");
                return 1;
            }
        }
        if (domains.Count == 0) {
            AnsiConsole.MarkupLine("[red]Provide at least one domain (argument or --domains-file).[/]");
            return 1;
        }

        var options = new CertificateInventoryCaptureOptions {
            CacheDirectory = CertificateInventoryCommandHelpers.ResolveCacheDirectory(settings.CacheDirectory),
            DnsEndpoint = settings.DnsEndpoint,
            IncludeApexHttps = !settings.NoApexHttps,
            IncludeWwwHttps = !settings.NoWwwHttps,
            IncludeMxHosts = !settings.DisableMxDiscovery,
            IncludeMxHttps = settings.IncludeMxHttps,
            IncludeSmtpStartTls = !settings.DisableSmtpStartTls,
            IncludeSubmissionStartTls = !settings.DisableSubmissionStartTls,
            IncludeImapTls = settings.IncludeImapTls,
            IncludePop3Tls = settings.IncludePop3Tls,
            MaxMxHostsPerDomain = settings.MaxMxHostsPerDomain,
            MaxParallelism = settings.MaxParallelism,
            DiscoveryParallelism = settings.DiscoveryParallelism,
            MailTimeout = TimeSpan.FromSeconds(settings.MailTimeoutSeconds),
            SkipRevocation = settings.SkipRevocation,
            CtProfile = settings.CtProfile,
            IncludeDefaultCtTemplate = !settings.DisableDefaultCtTemplate,
            EnableCensysCtSource = settings.EnableCensysCtSource,
            CensysApiId = settings.CensysApiId,
            CensysApiSecret = censysSecret,
            CensysCtApiUrlTemplate = settings.CensysCtApiUrlTemplate,
            EnableShodanCtSource = settings.EnableShodanCtSource,
            ShodanApiKey = shodanApiKey,
            ShodanCtApiUrlTemplate = settings.ShodanCtApiUrlTemplate,
            PersistSnapshot = !settings.NoPersist
        };
        if (settings.AdditionalEndpoints != null && settings.AdditionalEndpoints.Length > 0) {
            options.AdditionalEndpoints.AddRange(settings.AdditionalEndpoints.Where(endpoint => !string.IsNullOrWhiteSpace(endpoint)).Select(endpoint => endpoint.Trim()));
        }
        if (settings.CtApiTemplates != null && settings.CtApiTemplates.Length > 0) {
            options.CtApiTemplates.AddRange(settings.CtApiTemplates.Where(template => !string.IsNullOrWhiteSpace(template)).Select(template => template.Trim()));
        }

        var capture = new CertificateInventoryCapture();
        var logger = new InternalLogger(false);
        CertificateInventoryCaptureResult result;
        try {
            result = await capture.CaptureAsync(domains, options, logger, Program.CancellationToken).ConfigureAwait(false);
        } catch (OperationCanceledException) {
            AnsiConsole.MarkupLine("[yellow]Capture canceled.[/]");
            return 1;
        } catch (Exception ex) {
            AnsiConsole.MarkupLine($"[red]Capture failed:[/] {ex.Message}");
            return 1;
        }

        if (!string.IsNullOrWhiteSpace(settings.CsvPath)) {
            try {
                WriteCsv(result, settings.CsvPath!);
                AnsiConsole.MarkupLine($"[grey]CSV written:[/] {settings.CsvPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write CSV:[/] {ex.Message}");
                return 1;
            }
        }
        if (!string.IsNullOrWhiteSpace(settings.NdjsonPath)) {
            try {
                WriteNdjson(result, settings.NdjsonPath!);
                AnsiConsole.MarkupLine($"[grey]NDJSON written:[/] {settings.NdjsonPath}");
            } catch (Exception ex) {
                AnsiConsole.MarkupLine($"[red]Failed to write NDJSON:[/] {ex.Message}");
                return 1;
            }
        }

        if (settings.Json) {
            Console.WriteLine(JsonSerializer.Serialize(result, JsonOptions.Default));
            return 0;
        }

        var summary = new Table().Border(TableBorder.Rounded).Title("Certificate Inventory Capture");
        summary.AddColumn("Metric");
        summary.AddColumn("Value");
        summary.AddRow("CapturedAtUtc", result.CapturedAtUtc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss"));
        summary.AddRow("Domains", result.DomainCount.ToString());
        summary.AddRow("MX Hosts", result.MxHostCount.ToString());
        summary.AddRow("HTTPS Endpoints", result.HttpsEndpointCount.ToString());
        summary.AddRow("Mail Endpoints", result.MailEndpointCount.ToString());
        summary.AddRow("Snapshot Entries", result.EntryCount.ToString());
        summary.AddRow("Unique Endpoints", result.UniqueEndpointCount.ToString());
        summary.AddRow("Valid", result.ValidCount.ToString());
        summary.AddRow("Expired", result.ExpiredCount.ToString());
        summary.AddRow("Failed (no cert)", result.FailedCount.ToString());
        summary.AddRow("Snapshot Path", string.IsNullOrWhiteSpace(result.SnapshotPath) ? "-" : result.SnapshotPath);
        AnsiConsole.Write(summary);

        if (result.Warnings.Count > 0) {
            var warningTable = new Table().Border(TableBorder.Rounded);
            warningTable.Title = new TableTitle("Warnings");
            warningTable.AddColumn("Message");
            foreach (var warning in result.Warnings.Take(50)) {
                warningTable.AddRow(Markup.Escape(warning));
            }
            if (result.Warnings.Count > 50) {
                warningTable.AddRow($"... {result.Warnings.Count - 50} more warning(s)");
            }
            AnsiConsole.Write(warningTable);
        }

        if (settings.ShowEndpoints) {
            var endpointTable = new Table().Border(TableBorder.Rounded);
            endpointTable.Title = new TableTitle("Endpoints");
            endpointTable.AddColumn("Type");
            endpointTable.AddColumn("Endpoint");
            foreach (var endpoint in result.HttpsEndpoints.Take(500)) {
                endpointTable.AddRow("HTTPS", Markup.Escape(endpoint));
            }
            foreach (var endpoint in result.MailEndpoints.Take(500)) {
                endpointTable.AddRow("MAILTLS", Markup.Escape(endpoint));
            }
            AnsiConsole.Write(endpointTable);
        }

        return 0;
    }

    private static void WriteCsv(CertificateInventoryCaptureResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        sb.AppendLine("CapturedAtUtc,Host,ResolvedHost,Service,Scheme,Port,CertificateThumbprint,CertificateSerialNumber,CertificateSubject,CertificateIssuer,CertificateRootIssuer,NotAfterUtc,DaysToExpire,Valid,Expired,IsReachable,HostnameMatch,ChainComplete,AuthenticationProfile,AllowsServerAuthentication,AllowsClientAuthentication,AllowsSecureEmail,PresentInCtLogs,CtDiscoverySources,CtTemplateFormatErrors,CertificateChainSource");
        foreach (var entry in result.Snapshot.Entries) {
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(result.CapturedAtUtc.UtcDateTime.ToString("O")));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.Host));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.ResolvedHost));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.Service));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.Scheme));
            sb.Append(',');
            sb.Append(entry.Port);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateThumbprint));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateSerialNumber));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateSubject));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateRootIssuer));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.NotAfterUtc?.UtcDateTime.ToString("O") ?? string.Empty));
            sb.Append(',');
            sb.Append(entry.DaysToExpire);
            sb.Append(',');
            sb.Append(entry.Valid);
            sb.Append(',');
            sb.Append(entry.Expired);
            sb.Append(',');
            sb.Append(entry.IsReachable);
            sb.Append(',');
            sb.Append(entry.HostnameMatch);
            sb.Append(',');
            sb.Append(entry.ChainComplete);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.AuthenticationProfile));
            sb.Append(',');
            sb.Append(entry.AllowsServerAuthentication);
            sb.Append(',');
            sb.Append(entry.AllowsClientAuthentication);
            sb.Append(',');
            sb.Append(entry.AllowsSecureEmail);
            sb.Append(',');
            sb.Append(entry.PresentInCtLogs);
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", entry.CtDiscoverySources ?? Array.Empty<string>())));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(string.Join("|", entry.CtTemplateFormatErrors ?? Array.Empty<string>())));
            sb.Append(',');
            sb.Append(CertificateInventoryCommandHelpers.EscapeCsv(entry.CertificateChainSource));
            sb.AppendLine();
        }

        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static void WriteNdjson(CertificateInventoryCaptureResult result, string path) {
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) {
            Directory.CreateDirectory(directory);
        }

        var sb = new StringBuilder();
        foreach (var entry in result.Snapshot.Entries) {
            sb.AppendLine(CertificateInventoryCommandHelpers.SerializeJsonLine(new {
                result.CapturedAtUtc,
                Entry = entry
            }));
        }
        CertificateInventoryCommandHelpers.WriteUtf8Text(fullPath, sb.ToString());
    }

    private static string? ResolveSecret(string? directValue, string? envVariableName) {
        if (!string.IsNullOrWhiteSpace(directValue)) {
            return directValue;
        }
        if (envVariableName == null) {
            return null;
        }
        var trimmedName = envVariableName.Trim();
        if (trimmedName.Length == 0) {
            return null;
        }
        return Environment.GetEnvironmentVariable(trimmedName);
    }
}
