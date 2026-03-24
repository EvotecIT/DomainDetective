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

    [Description("Discover CT-observed subdomains and probe them over HTTPS.")]
    [CommandOption("--include-ct-subdomains")]
    public bool IncludeCtSubdomains { get; set; }

    [Description("When CT subdomain discovery is enabled, only include CT subdomains that currently resolve in DNS.")]
    [CommandOption("--verify-ct-subdomains")]
    public bool VerifyCtSubdomains { get; set; }

    [Description("Maximum CT rows processed per domain for CT subdomain discovery (0 means no explicit cap override).")]
    [CommandOption("--ct-max-rows-per-domain <N>")]
    [DefaultValue(10000)]
    public int MaxCtRowsPerDomain { get; set; } = 10000;

    [Description("Maximum CT subdomains retained per domain for CT subdomain discovery (0 means no explicit cap override).")]
    [CommandOption("--ct-max-subdomains-per-domain <N>")]
    [DefaultValue(2000)]
    public int MaxCtSubdomainsPerDomain { get; set; } = 2000;

    [Description("Enable native RFC6962 CT log polling for CT subdomain discovery.")]
    [CommandOption("--enable-native-ct-logs")]
    public bool EnableNativeCtLogs { get; set; }

    [Description("Disable shared native CT ingestion pass across all domains (uses per-domain native CT discovery).")]
    [CommandOption("--disable-native-ct-shared-ingestion")]
    public bool DisableNativeCtSharedIngestion { get; set; }

    [Description("Use only native CT log polling for CT subdomain discovery (skip crt.sh/Cert Spotter).")]
    [CommandOption("--native-ct-log-only")]
    public bool NativeCtLogOnly { get; set; }

    [Description("Enable passive/public CT fallback for CT subdomain discovery.")]
    [CommandOption("--enable-passive-ct-fallback")]
    public bool EnablePassiveCtFallback { get; set; }

    [Description("Enable passive/public CT metadata rescue without broadly enabling passive CT discovery fallback.")]
    [CommandOption("--enable-passive-ct-metadata-fallback")]
    public bool EnablePassiveCtMetadataFallback { get; set; }

    [Description("Timeout in seconds for each passive/public CT HTTP request.")]
    [CommandOption("--passive-ct-request-timeout-seconds <N>")]
    [DefaultValue(15)]
    public int PassiveCtRequestTimeoutSeconds { get; set; } = 15;

    [Description("Maximum retry count for transient passive/public CT HTTP failures.")]
    [CommandOption("--passive-ct-retry-count <N>")]
    [DefaultValue(2)]
    public int PassiveCtRetryCount { get; set; } = 2;

    [Description("Base delay in milliseconds between passive/public CT retry attempts.")]
    [CommandOption("--passive-ct-retry-base-delay-ms <N>")]
    [DefaultValue(750)]
    public int PassiveCtRetryBaseDelayMilliseconds { get; set; } = 750;

    [Description("Maximum delay in milliseconds between passive/public CT retry attempts.")]
    [CommandOption("--passive-ct-retry-max-delay-ms <N>")]
    [DefaultValue(15000)]
    public int PassiveCtRetryMaxDelayMilliseconds { get; set; } = 15000;

    [Description("Cooldown in seconds applied to passive/public CT sources after transient failures or rate limits.")]
    [CommandOption("--passive-ct-source-cooldown-seconds <N>")]
    [DefaultValue(60)]
    public int PassiveCtSourceCooldownSeconds { get; set; } = 60;

    [Description("Native CT log list URL used to resolve CT logs.")]
    [CommandOption("--native-ct-log-list-url <URL>")]
    public string NativeCtLogListUrl { get; set; } = "https://www.gstatic.com/ct/log_list/v3/log_list.json";

    [Description("Explicit native CT log URL(s). Repeat for multiple values.")]
    [CommandOption("--native-ct-log-url <URL>")]
    public string[] NativeCtLogUrls { get; set; } = Array.Empty<string>();

    [Description("Maximum CT logs processed per domain when native CT polling is enabled (0 means all).")]
    [CommandOption("--native-ct-max-logs <N>")]
    [DefaultValue(12)]
    public int NativeCtMaxLogs { get; set; } = 12;

    [Description("Maximum CT entries processed per log per domain when native CT polling is enabled (0 means uncapped).")]
    [CommandOption("--native-ct-max-entries-per-log <N>")]
    [DefaultValue(2000)]
    public int NativeCtMaxEntriesPerLog { get; set; } = 2000;

    [Description("Maximum get-entries batch size for native CT polling.")]
    [CommandOption("--native-ct-entry-batch-size <N>")]
    [DefaultValue(256)]
    public int NativeCtEntryBatchSize { get; set; } = 256;

    [Description("Initial per-log backfill when native CT cursor is missing (0 starts at current tree head).")]
    [CommandOption("--native-ct-initial-backfill-per-log <N>")]
    [DefaultValue(2000)]
    public int NativeCtInitialBackfillEntriesPerLog { get; set; } = 2000;

    [Description("Optional native CT cursor state file path.")]
    [CommandOption("--native-ct-cursor-state-path <PATH>")]
    public string? NativeCtCursorStatePath { get; set; }

    [Description("Include pending logs from CT log list when native polling is enabled.")]
    [CommandOption("--native-ct-include-pending-logs")]
    public bool NativeCtIncludePendingLogs { get; set; }

    [Description("Delay in milliseconds between native CT requests.")]
    [CommandOption("--native-ct-request-delay-ms <N>")]
    [DefaultValue(0)]
    public int NativeCtRequestDelayMilliseconds { get; set; }

    [Description("Timeout in seconds for each native CT HTTP request.")]
    [CommandOption("--native-ct-request-timeout-seconds <N>")]
    [DefaultValue(15)]
    public int NativeCtRequestTimeoutSeconds { get; set; } = 15;

    [Description("Maximum retry count for transient native CT HTTP failures.")]
    [CommandOption("--native-ct-retry-count <N>")]
    [DefaultValue(3)]
    public int NativeCtRetryCount { get; set; } = 3;

    [Description("Base delay in milliseconds between native CT retry attempts.")]
    [CommandOption("--native-ct-retry-base-delay-ms <N>")]
    [DefaultValue(500)]
    public int NativeCtRetryBaseDelayMilliseconds { get; set; } = 500;

    [Description("Maximum delay in milliseconds between native CT retry attempts.")]
    [CommandOption("--native-ct-retry-max-delay-ms <N>")]
    [DefaultValue(10000)]
    public int NativeCtRetryMaxDelayMilliseconds { get; set; } = 10000;

    [Description("Consecutive native CT failures required before opening per-log circuit breaker.")]
    [CommandOption("--native-ct-circuit-breaker-threshold <N>")]
    [DefaultValue(3)]
    public int NativeCtCircuitBreakerFailureThreshold { get; set; } = 3;

    [Description("Native CT circuit-breaker open duration in seconds.")]
    [CommandOption("--native-ct-circuit-breaker-duration-seconds <N>")]
    [DefaultValue(600)]
    public int NativeCtCircuitBreakerDurationSeconds { get; set; } = 600;

    [Description("Disable native CT catch-up mode that expands limits when cursor lag is high.")]
    [CommandOption("--disable-native-ct-catch-up")]
    public bool DisableNativeCtCatchUpMode { get; set; }

    [Description("Native CT cursor lag threshold that enables catch-up mode.")]
    [CommandOption("--native-ct-catch-up-lag-threshold <N>")]
    [DefaultValue(50000)]
    public int NativeCtCatchUpLagThreshold { get; set; } = 50000;

    [Description("Maximum CT entries per log while native CT catch-up mode is active.")]
    [CommandOption("--native-ct-catch-up-max-entries-per-log <N>")]
    [DefaultValue(20000)]
    public int NativeCtCatchUpMaxEntriesPerLog { get; set; } = 20000;

    [Description("Maximum get-entries batch size while native CT catch-up mode is active.")]
    [CommandOption("--native-ct-catch-up-batch-size <N>")]
    [DefaultValue(1024)]
    public int NativeCtCatchUpBatchSize { get; set; } = 1024;

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

    [Description("HTTPS certificate probe timeout in seconds.")]
    [CommandOption("--https-timeout-seconds <SECONDS>")]
    [DefaultValue(30)]
    public int HttpsTimeoutSeconds { get; set; } = 30;

    [Description("Maximum total probe targets (HTTPS + mail) kept after discovery (0 means unlimited).")]
    [CommandOption("--max-targets <N>")]
    [DefaultValue(0)]
    public int MaxTargets { get; set; }

    [Description("Maximum number of probe starts per second (0 means unlimited).")]
    [CommandOption("--max-probe-starts-per-second <N>")]
    [DefaultValue(0)]
    public int MaxProbeStartsPerSecond { get; set; }

    [Description("Reuse recent persisted endpoint results to avoid re-probing unchanged endpoints.")]
    [CommandOption("--reuse-recent-results")]
    public bool ReuseRecentResults { get; set; }

    [Description("Maximum age in hours of persisted endpoint results used for reuse.")]
    [CommandOption("--recent-result-ttl-hours <N>")]
    [DefaultValue(24)]
    public int RecentResultTtlHours { get; set; } = 24;

    [Description("Reuse recent persisted stable failures to avoid immediately re-probing dead or timeout-heavy endpoints.")]
    [CommandOption("--reuse-recent-failures")]
    public bool ReuseRecentFailures { get; set; }

    [Description("Maximum age in hours of persisted stable failures used for reuse.")]
    [CommandOption("--recent-failure-result-ttl-hours <N>")]
    [DefaultValue(1)]
    public int RecentFailureResultTtlHours { get; set; } = 1;

    [Description("Always re-probe endpoints with certificates expiring within this many days.")]
    [CommandOption("--reprobe-expiring-within-days <N>")]
    [DefaultValue(14)]
    public int ReprobeExpiringWithinDays { get; set; } = 14;

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
        if (settings.HttpsTimeoutSeconds < 1 || settings.HttpsTimeoutSeconds > 300) {
            AnsiConsole.MarkupLine("[red]--https-timeout-seconds must be between 1 and 300.[/]");
            return 1;
        }
        if (settings.MaxTargets < 0) {
            AnsiConsole.MarkupLine("[red]--max-targets must be 0 or greater.[/]");
            return 1;
        }
        if (settings.MaxProbeStartsPerSecond < 0) {
            AnsiConsole.MarkupLine("[red]--max-probe-starts-per-second must be 0 or greater.[/]");
            return 1;
        }
        if (settings.RecentResultTtlHours < 0) {
            AnsiConsole.MarkupLine("[red]--recent-result-ttl-hours must be 0 or greater.[/]");
            return 1;
        }
        if (settings.RecentFailureResultTtlHours < 0) {
            AnsiConsole.MarkupLine("[red]--recent-failure-result-ttl-hours must be 0 or greater.[/]");
            return 1;
        }
        if (settings.ReprobeExpiringWithinDays < 0) {
            AnsiConsole.MarkupLine("[red]--reprobe-expiring-within-days must be 0 or greater.[/]");
            return 1;
        }
        if (settings.MaxCtRowsPerDomain < 0) {
            AnsiConsole.MarkupLine("[red]--ct-max-rows-per-domain must be 0 or greater.[/]");
            return 1;
        }
        if (settings.MaxCtSubdomainsPerDomain < 0) {
            AnsiConsole.MarkupLine("[red]--ct-max-subdomains-per-domain must be 0 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtMaxLogs < 0) {
            AnsiConsole.MarkupLine("[red]--native-ct-max-logs must be 0 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtMaxEntriesPerLog < 0) {
            AnsiConsole.MarkupLine("[red]--native-ct-max-entries-per-log must be 0 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtEntryBatchSize < 1 || settings.NativeCtEntryBatchSize > 2048) {
            AnsiConsole.MarkupLine("[red]--native-ct-entry-batch-size must be between 1 and 2048.[/]");
            return 1;
        }
        if (settings.NativeCtInitialBackfillEntriesPerLog < 0) {
            AnsiConsole.MarkupLine("[red]--native-ct-initial-backfill-per-log must be 0 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtRequestDelayMilliseconds < 0 || settings.NativeCtRequestDelayMilliseconds > 60000) {
            AnsiConsole.MarkupLine("[red]--native-ct-request-delay-ms must be between 0 and 60000.[/]");
            return 1;
        }
        if (settings.NativeCtRequestTimeoutSeconds < 1 || settings.NativeCtRequestTimeoutSeconds > 300) {
            AnsiConsole.MarkupLine("[red]--native-ct-request-timeout-seconds must be between 1 and 300.[/]");
            return 1;
        }
        if (settings.PassiveCtRequestTimeoutSeconds < 1 || settings.PassiveCtRequestTimeoutSeconds > 300) {
            AnsiConsole.MarkupLine("[red]--passive-ct-request-timeout-seconds must be between 1 and 300.[/]");
            return 1;
        }
        if (settings.PassiveCtRetryCount < 0 || settings.PassiveCtRetryCount > 20) {
            AnsiConsole.MarkupLine("[red]--passive-ct-retry-count must be between 0 and 20.[/]");
            return 1;
        }
        if (settings.PassiveCtRetryBaseDelayMilliseconds < 0 || settings.PassiveCtRetryBaseDelayMilliseconds > 60000) {
            AnsiConsole.MarkupLine("[red]--passive-ct-retry-base-delay-ms must be between 0 and 60000.[/]");
            return 1;
        }
        if (settings.PassiveCtRetryMaxDelayMilliseconds < 0 || settings.PassiveCtRetryMaxDelayMilliseconds > 300000) {
            AnsiConsole.MarkupLine("[red]--passive-ct-retry-max-delay-ms must be between 0 and 300000.[/]");
            return 1;
        }
        if (settings.PassiveCtSourceCooldownSeconds < 0 || settings.PassiveCtSourceCooldownSeconds > 86400) {
            AnsiConsole.MarkupLine("[red]--passive-ct-source-cooldown-seconds must be between 0 and 86400.[/]");
            return 1;
        }
        if (settings.NativeCtRetryCount < 0 || settings.NativeCtRetryCount > 20) {
            AnsiConsole.MarkupLine("[red]--native-ct-retry-count must be between 0 and 20.[/]");
            return 1;
        }
        if (settings.NativeCtRetryBaseDelayMilliseconds < 0 || settings.NativeCtRetryBaseDelayMilliseconds > 60000) {
            AnsiConsole.MarkupLine("[red]--native-ct-retry-base-delay-ms must be between 0 and 60000.[/]");
            return 1;
        }
        if (settings.NativeCtRetryMaxDelayMilliseconds < 0 || settings.NativeCtRetryMaxDelayMilliseconds > 300000) {
            AnsiConsole.MarkupLine("[red]--native-ct-retry-max-delay-ms must be between 0 and 300000.[/]");
            return 1;
        }
        if (settings.NativeCtCircuitBreakerFailureThreshold < 1 || settings.NativeCtCircuitBreakerFailureThreshold > 100) {
            AnsiConsole.MarkupLine("[red]--native-ct-circuit-breaker-threshold must be between 1 and 100.[/]");
            return 1;
        }
        if (settings.NativeCtCircuitBreakerDurationSeconds < 1 || settings.NativeCtCircuitBreakerDurationSeconds > 86400) {
            AnsiConsole.MarkupLine("[red]--native-ct-circuit-breaker-duration-seconds must be between 1 and 86400.[/]");
            return 1;
        }
        if (settings.NativeCtCatchUpLagThreshold < 1) {
            AnsiConsole.MarkupLine("[red]--native-ct-catch-up-lag-threshold must be 1 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtCatchUpMaxEntriesPerLog < 0) {
            AnsiConsole.MarkupLine("[red]--native-ct-catch-up-max-entries-per-log must be 0 or greater.[/]");
            return 1;
        }
        if (settings.NativeCtCatchUpBatchSize < 1 || settings.NativeCtCatchUpBatchSize > 2048) {
            AnsiConsole.MarkupLine("[red]--native-ct-catch-up-batch-size must be between 1 and 2048.[/]");
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
            IncludeCtDiscoveredSubdomains = settings.IncludeCtSubdomains,
            VerifyCtDiscoveredSubdomains = settings.VerifyCtSubdomains,
            MaxCtRowsPerDomain = settings.MaxCtRowsPerDomain,
            MaxCtSubdomainsPerDomain = settings.MaxCtSubdomainsPerDomain,
            EnableNativeCtLogSubdomainSource = settings.EnableNativeCtLogs,
            EnableNativeCtSharedIngestion = !settings.DisableNativeCtSharedIngestion,
            NativeCtLogOnly = settings.NativeCtLogOnly,
            EnablePassiveCtFallback = settings.EnablePassiveCtFallback,
            EnablePassiveCtMetadataFallback = settings.EnablePassiveCtMetadataFallback,
            PassiveCtRequestTimeout = TimeSpan.FromSeconds(settings.PassiveCtRequestTimeoutSeconds),
            PassiveCtRetryCount = settings.PassiveCtRetryCount,
            PassiveCtRetryBaseDelay = TimeSpan.FromMilliseconds(settings.PassiveCtRetryBaseDelayMilliseconds),
            PassiveCtRetryMaxDelay = TimeSpan.FromMilliseconds(settings.PassiveCtRetryMaxDelayMilliseconds),
            PassiveCtSourceCooldown = TimeSpan.FromSeconds(settings.PassiveCtSourceCooldownSeconds),
            NativeCtLogListUrl = settings.NativeCtLogListUrl,
            NativeCtMaxLogs = settings.NativeCtMaxLogs,
            NativeCtMaxEntriesPerLog = settings.NativeCtMaxEntriesPerLog,
            NativeCtEntryBatchSize = settings.NativeCtEntryBatchSize,
            NativeCtInitialBackfillEntriesPerLog = settings.NativeCtInitialBackfillEntriesPerLog,
            NativeCtCursorStatePath = settings.NativeCtCursorStatePath,
            NativeCtIncludePendingLogs = settings.NativeCtIncludePendingLogs,
            NativeCtRequestDelay = TimeSpan.FromMilliseconds(settings.NativeCtRequestDelayMilliseconds),
            NativeCtRequestTimeout = TimeSpan.FromSeconds(settings.NativeCtRequestTimeoutSeconds),
            NativeCtRetryCount = settings.NativeCtRetryCount,
            NativeCtRetryBaseDelay = TimeSpan.FromMilliseconds(settings.NativeCtRetryBaseDelayMilliseconds),
            NativeCtRetryMaxDelay = TimeSpan.FromMilliseconds(settings.NativeCtRetryMaxDelayMilliseconds),
            NativeCtCircuitBreakerFailureThreshold = settings.NativeCtCircuitBreakerFailureThreshold,
            NativeCtCircuitBreakerDuration = TimeSpan.FromSeconds(settings.NativeCtCircuitBreakerDurationSeconds),
            NativeCtEnableCatchUpMode = !settings.DisableNativeCtCatchUpMode,
            NativeCtCatchUpLagThreshold = settings.NativeCtCatchUpLagThreshold,
            NativeCtCatchUpMaxEntriesPerLog = settings.NativeCtCatchUpMaxEntriesPerLog,
            NativeCtCatchUpBatchSize = settings.NativeCtCatchUpBatchSize,
            MaxMxHostsPerDomain = settings.MaxMxHostsPerDomain,
            MaxParallelism = settings.MaxParallelism,
            DiscoveryParallelism = settings.DiscoveryParallelism,
            MailTimeout = TimeSpan.FromSeconds(settings.MailTimeoutSeconds),
            HttpsTimeout = TimeSpan.FromSeconds(settings.HttpsTimeoutSeconds),
            MaxTargets = settings.MaxTargets,
            MaxProbeStartsPerSecond = settings.MaxProbeStartsPerSecond,
            ReuseRecentSnapshotEntries = settings.ReuseRecentResults,
            RecentSnapshotTtl = TimeSpan.FromHours(settings.RecentResultTtlHours),
            ReuseRecentFailureSnapshotEntries = settings.ReuseRecentFailures,
            RecentFailureSnapshotTtl = TimeSpan.FromHours(settings.RecentFailureResultTtlHours),
            ReprobeExpiringWithinDays = settings.ReprobeExpiringWithinDays,
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
        if (settings.NativeCtLogUrls != null && settings.NativeCtLogUrls.Length > 0) {
            options.NativeCtLogUrls.AddRange(settings.NativeCtLogUrls.Where(url => !string.IsNullOrWhiteSpace(url)).Select(url => url.Trim()));
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
        summary.AddRow("CT Subdomains", result.CtDiscoveredSubdomainCount.ToString());
        summary.AddRow("Native CT Log Diagnostics", result.NativeCtLogDiagnostics.Count.ToString());
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
