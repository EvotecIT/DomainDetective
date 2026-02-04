using DnsClientX;
using DomainDetective.Helpers;
using Spectre.Console;
using Spectre.Console.Cli;
using System;
using System.Text.Json;

namespace DomainDetective.CLI;

/// <summary>
/// Settings for <see cref="ValidateEmailCommand"/>.
/// </summary>
internal sealed class ValidateEmailSettings : CommandSettings {
    /// <summary>Email address to validate.</summary>
    [CommandArgument(0, "<email>")]
    public string Email { get; set; } = string.Empty;

    /// <summary>DNS endpoint to use.</summary>
    [CommandOption("--dns-endpoint <ENDPOINT>")]
    public string? DnsEndpoint { get; set; }

    /// <summary>Enable SMTP probe.</summary>
    [CommandOption("--smtp")]
    public bool SmtpProbe { get; set; }

    /// <summary>SMTP port.</summary>
    [CommandOption("--smtp-port <PORT>")]
    public int SmtpPort { get; set; } = 25;

    /// <summary>SMTP timeout (seconds).</summary>
    [CommandOption("--smtp-timeout <SECONDS>")]
    public int SmtpTimeoutSeconds { get; set; } = 20;

    /// <summary>Allow invalid SMTP TLS certificates when STARTTLS is used.</summary>
    [CommandOption("--smtp-allow-invalid-cert")]
    public bool AllowInvalidSmtpCertificates { get; set; }

    /// <summary>Max SMTP hosts to try.</summary>
    [CommandOption("--smtp-max-hosts <COUNT>")]
    public int SmtpMaxHosts { get; set; } = 1;

    /// <summary>SMTP retries on temporary failures.</summary>
    [CommandOption("--smtp-retries <COUNT>")]
    public int SmtpRetryCount { get; set; } = 1;

    /// <summary>SMTP retry delay (seconds).</summary>
    [CommandOption("--smtp-retry-delay <SECONDS>")]
    public int SmtpRetryDelaySeconds { get; set; } = 2;

    /// <summary>EHLO/HELO name.</summary>
    [CommandOption("--smtp-hello <NAME>")]
    public string? SmtpHelloName { get; set; }

    /// <summary>MAIL FROM address.</summary>
    [CommandOption("--smtp-from <ADDRESS>")]
    public string? SmtpFromAddress { get; set; }

    /// <summary>SMTP proxy host (SOCKS5).</summary>
    [CommandOption("--smtp-proxy-host <HOST>")]
    public string? SmtpProxyHost { get; set; }

    /// <summary>SMTP proxy port (SOCKS5).</summary>
    [CommandOption("--smtp-proxy-port <PORT>")]
    public int SmtpProxyPort { get; set; } = 1080;

    /// <summary>SMTP proxy username (SOCKS5).</summary>
    [CommandOption("--smtp-proxy-user <USER>")]
    public string? SmtpProxyUsername { get; set; }

    /// <summary>SMTP proxy password (SOCKS5).</summary>
    [CommandOption("--smtp-proxy-pass <PASS>")]
    public string? SmtpProxyPassword { get; set; }

    /// <summary>Enable catch-all detection.</summary>
    [CommandOption("--catch-all")]
    public bool CheckCatchAll { get; set; }

    /// <summary>Disable provider-specific SMTP rules.</summary>
    [CommandOption("--no-provider-rules")]
    public bool DisableProviderRules { get; set; }

    /// <summary>Allow international local parts.</summary>
    [CommandOption("--allow-international")]
    public bool AllowInternational { get; set; }

    /// <summary>Allow top-level-only domains.</summary>
    [CommandOption("--allow-tld")]
    public bool AllowTopLevelDomains { get; set; }

    /// <summary>Check for Gravatar existence.</summary>
    [CommandOption("--gravatar")]
    public bool CheckGravatar { get; set; }

    /// <summary>Check Have I Been Pwned breach status.</summary>
    [CommandOption("--hibp")]
    public bool CheckHaveIBeenPwned { get; set; }

    /// <summary>Have I Been Pwned API key.</summary>
    [CommandOption("--hibp-api-key <KEY>")]
    public string? HaveIBeenPwnedApiKey { get; set; }

    /// <summary>Override disposable domain list.</summary>
    [CommandOption("--disposable-domains <PATH>")]
    public string? DisposableDomainsPath { get; set; }

    /// <summary>Override role account list.</summary>
    [CommandOption("--role-accounts <PATH>")]
    public string? RoleAccountsPath { get; set; }

    /// <summary>Override free provider list.</summary>
    [CommandOption("--free-providers <PATH>")]
    public string? FreeProvidersPath { get; set; }

    /// <summary>Override B2C provider list.</summary>
    [CommandOption("--b2c-providers <PATH>")]
    public string? B2CProvidersPath { get; set; }

    /// <summary>SMTP rules JSON path.</summary>
    [CommandOption("--smtp-rules <PATH>")]
    public string? SmtpRulesPath { get; set; }

    /// <summary>Disable built-in SMTP rules.</summary>
    [CommandOption("--no-builtin-smtp-rules")]
    public bool DisableBuiltinSmtpRules { get; set; }

    /// <summary>Allow catch-all probing for B2C providers.</summary>
    [CommandOption("--allow-b2c-catch-all")]
    public bool AllowB2CCatchAll { get; set; }

    /// <summary>Enable provider web checks when available.</summary>
    [CommandOption("--provider-web")]
    public bool EnableProviderWebChecks { get; set; }

    /// <summary>Proton AUTH cookie value (AUTH-&lt;uid&gt; or raw value).</summary>
    [CommandOption("--proton-auth <VALUE>")]
    public string? ProtonAuthCookie { get; set; }

    /// <summary>Proton uid value used for x-pm-uid.</summary>
    [CommandOption("--proton-uid <VALUE>")]
    public string? ProtonUid { get; set; }

    /// <summary>Output JSON results.</summary>
    [CommandOption("--json")]
    public bool Json { get; set; }
}

/// <summary>
/// Validates an email address.
/// </summary>
internal sealed class ValidateEmailCommand : AsyncCommand<ValidateEmailSettings> {
    /// <inheritdoc/>
    public override async Task<int> ExecuteAsync(CommandContext context, ValidateEmailSettings settings) {
        var dnsEndpoint = DnsEndpoint.System;
        if (!string.IsNullOrWhiteSpace(settings.DnsEndpoint)) {
            if (!Enum.TryParse(settings.DnsEndpoint, true, out dnsEndpoint)) {
                AnsiConsole.MarkupLine($"[yellow]Invalid --dns-endpoint value: {settings.DnsEndpoint}. Using system DNS.[/]");
                dnsEndpoint = DnsEndpoint.System;
            }
        }

        var hc = new DomainHealthCheck(dnsEndpoint);
        var options = new EmailAddressValidationOptions {
            AllowInternational = settings.AllowInternational,
            AllowTopLevelDomains = settings.AllowTopLevelDomains,
            CheckSmtp = settings.SmtpProbe,
            CheckCatchAll = settings.CheckCatchAll,
            SmtpPort = settings.SmtpPort,
            SmtpTimeout = TimeSpan.FromSeconds(settings.SmtpTimeoutSeconds),
            AllowInvalidSmtpCertificates = settings.AllowInvalidSmtpCertificates,
            SmtpMaxHosts = settings.SmtpMaxHosts,
            SmtpRetryCount = settings.SmtpRetryCount,
            SmtpRetryDelay = TimeSpan.FromSeconds(settings.SmtpRetryDelaySeconds),
            SmtpHelloName = settings.SmtpHelloName,
            SmtpFromAddress = settings.SmtpFromAddress,
            ApplyProviderPolicies = !settings.DisableProviderRules,
            DisableCatchAllForB2C = !settings.AllowB2CCatchAll,
            EnableProviderWebChecks = settings.EnableProviderWebChecks,
            ProtonAuthCookie = settings.ProtonAuthCookie,
            ProtonUid = settings.ProtonUid,
            CheckGravatar = settings.CheckGravatar,
            CheckHaveIBeenPwned = settings.CheckHaveIBeenPwned || !string.IsNullOrWhiteSpace(settings.HaveIBeenPwnedApiKey),
            HaveIBeenPwnedApiKey = settings.HaveIBeenPwnedApiKey,
            DisposableDomainsPath = settings.DisposableDomainsPath,
            RoleAccountsPath = settings.RoleAccountsPath,
            FreeProvidersPath = settings.FreeProvidersPath,
            B2CProvidersPath = settings.B2CProvidersPath,
            SmtpRulesPath = settings.SmtpRulesPath,
            UseBuiltinSmtpRules = !settings.DisableBuiltinSmtpRules
        };
        if (!string.IsNullOrWhiteSpace(settings.SmtpProxyHost)) {
            options.SmtpProxy = new EmailSmtpProxyOptions {
                Host = settings.SmtpProxyHost,
                Port = settings.SmtpProxyPort,
                Username = settings.SmtpProxyUsername,
                Password = settings.SmtpProxyPassword
            };
        }

        await hc.VerifyEmailAddress(settings.Email, options, Program.CancellationToken);
        var result = hc.EmailAddressValidationAnalysis;

        if (settings.Json) {
            var json = JsonSerializer.Serialize(result, JsonOptions.Default);
            Console.WriteLine(json);
        } else {
            CliHelpers.ShowPropertiesTable($"Email validation for {settings.Email}", result, false);
        }
        return 0;
    }
}
