using DnsClientX;
using System.Management.Automation;
using System.Threading.Tasks;

namespace DomainDetective.PowerShell;

/// <summary>Validates an email address using syntax, DNS, and optional SMTP checks.</summary>
/// <para>Part of the DomainDetective project.</para>
/// <example>
///   <summary>Validate an email address using DNS checks.</summary>
///   <code>Test-DDEmailAddress -EmailAddress user@example.com</code>
/// </example>
/// <example>
///   <summary>Include SMTP probing and catch-all detection.</summary>
///   <code>Test-DDEmailAddress -EmailAddress user@example.com -SmtpProbe -CheckCatchAll</code>
/// </example>
/// <example>
///   <summary>Use provider web checks for Proton with authenticated session values.</summary>
///   <code>Test-DDEmailAddress -EmailAddress user@proton.me -SmtpProbe -EnableProviderWebChecks -ProtonAuthCookie "AUTH-&lt;uid&gt;=&lt;value&gt;" -ProtonUid "&lt;uid&gt;"</code>
/// </example>
[Cmdlet(VerbsDiagnostic.Test, "DDEmailAddress")]
[Alias("Test-EmailAddress")]
public sealed class CmdletTestEmailAddress : ExportableAsyncPSCmdlet {
    /// <summary>Email address to validate.</summary>
    [Parameter(Mandatory = true, Position = 0)]
    [ValidateNotNullOrEmpty]
    public string EmailAddress = string.Empty;

    /// <summary>DNS server used for queries.</summary>
    [Parameter(Mandatory = false, Position = 1)]
    public DnsEndpoint DnsEndpoint = DnsEndpoint.System;

    /// <summary>Allow international characters in local parts.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AllowInternational;

    /// <summary>Allow top-level-only domains.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AllowTopLevelDomains;

    /// <summary>Enable SMTP probe for deliverability.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter SmtpProbe;

    /// <summary>Enable catch-all detection when SMTP probing.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CheckCatchAll;

    /// <summary>SMTP port for probing.</summary>
    [Parameter(Mandatory = false)]
    public int SmtpPort = 25;

    /// <summary>SMTP timeout in seconds.</summary>
    [Parameter(Mandatory = false)]
    public int SmtpTimeoutSeconds = 20;

    /// <summary>Allow invalid SMTP TLS certificates when STARTTLS is used.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AllowInvalidSmtpCertificates;

    /// <summary>Max SMTP hosts to try.</summary>
    [Parameter(Mandatory = false)]
    public int SmtpMaxHosts = 1;

    /// <summary>SMTP retries on temporary failures.</summary>
    [Parameter(Mandatory = false)]
    public int SmtpRetryCount = 1;

    /// <summary>SMTP retry delay in seconds.</summary>
    [Parameter(Mandatory = false)]
    public int SmtpRetryDelaySeconds = 2;

    /// <summary>EHLO/HELO name to present.</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpHelloName;

    /// <summary>MAIL FROM address to use.</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpFromAddress;

    /// <summary>SMTP proxy host (SOCKS5).</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpProxyHost;

    /// <summary>SMTP proxy port (SOCKS5).</summary>
    [Parameter(Mandatory = false)]
    public int SmtpProxyPort = 1080;

    /// <summary>SMTP proxy username (SOCKS5).</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpProxyUsername;

    /// <summary>SMTP proxy password (SOCKS5).</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpProxyPassword;

    /// <summary>Check for an existing Gravatar image.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CheckGravatar;

    /// <summary>Disable provider-specific SMTP rules.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableProviderRules;

    /// <summary>Check Have I Been Pwned breach status.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter CheckHaveIBeenPwned;

    /// <summary>Have I Been Pwned API key.</summary>
    [Parameter(Mandatory = false)]
    public string? HaveIBeenPwnedApiKey;

    /// <summary>Override disposable domain list path.</summary>
    [Parameter(Mandatory = false)]
    public string? DisposableDomainsPath;

    /// <summary>Override role account list path.</summary>
    [Parameter(Mandatory = false)]
    public string? RoleAccountsPath;

    /// <summary>Override free provider list path.</summary>
    [Parameter(Mandatory = false)]
    public string? FreeProvidersPath;

    /// <summary>Override B2C provider list path.</summary>
    [Parameter(Mandatory = false)]
    public string? B2CProvidersPath;

    /// <summary>SMTP rules JSON path.</summary>
    [Parameter(Mandatory = false)]
    public string? SmtpRulesPath;

    /// <summary>Disable built-in SMTP rules.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter DisableBuiltinSmtpRules;

    /// <summary>Allow catch-all probing for B2C providers.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter AllowB2CCatchAll;

    /// <summary>Enable provider web checks when available.</summary>
    [Parameter(Mandatory = false)]
    public SwitchParameter EnableProviderWebChecks;

    /// <summary>Proton AUTH cookie value (AUTH-&lt;uid&gt; or raw value).</summary>
    [Parameter(Mandatory = false)]
    public string? ProtonAuthCookie;

    /// <summary>Proton uid value used for x-pm-uid.</summary>
    [Parameter(Mandatory = false)]
    public string? ProtonUid;

    private InternalLogger _logger = null!;
    private DomainHealthCheck _healthCheck = null!;

    /// <summary>Initializes logging and helper classes.</summary>
    /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override Task BeginProcessingAsync() {
        _logger = new InternalLogger(false);
        var psLogger = new InternalLoggerPowerShell(_logger, WriteVerbose, WriteWarning, WriteDebug, WriteError, WriteProgress, WriteInformation);
        psLogger.ResetActivityIdCounter();
        _healthCheck = new DomainHealthCheck(DnsEndpoint, _logger);
        ApplyExecutionOptions(_healthCheck);
        return Task.CompletedTask;
    }

    /// <summary>Executes the cmdlet operation.</summary>
    /// <returns>A <see cref="System.Threading.Tasks.Task"/> representing the asynchronous operation.</returns>
    protected override async Task ProcessRecordAsync() {
        var options = new EmailAddressValidationOptions {
            AllowInternational = AllowInternational.IsPresent,
            AllowTopLevelDomains = AllowTopLevelDomains.IsPresent,
            CheckSmtp = SmtpProbe.IsPresent,
            CheckCatchAll = CheckCatchAll.IsPresent,
            SmtpPort = SmtpPort,
            SmtpTimeout = System.TimeSpan.FromSeconds(SmtpTimeoutSeconds),
            AllowInvalidSmtpCertificates = AllowInvalidSmtpCertificates.IsPresent,
            SmtpMaxHosts = SmtpMaxHosts,
            SmtpRetryCount = SmtpRetryCount,
            SmtpRetryDelay = System.TimeSpan.FromSeconds(SmtpRetryDelaySeconds),
            SmtpHelloName = SmtpHelloName,
            SmtpFromAddress = SmtpFromAddress,
            ApplyProviderPolicies = !DisableProviderRules.IsPresent,
            DisableCatchAllForB2C = !AllowB2CCatchAll.IsPresent,
            EnableProviderWebChecks = EnableProviderWebChecks.IsPresent,
            ProtonAuthCookie = ProtonAuthCookie,
            ProtonUid = ProtonUid,
            CheckGravatar = CheckGravatar.IsPresent,
            CheckHaveIBeenPwned = CheckHaveIBeenPwned.IsPresent || !string.IsNullOrWhiteSpace(HaveIBeenPwnedApiKey),
            HaveIBeenPwnedApiKey = HaveIBeenPwnedApiKey,
            DisposableDomainsPath = DisposableDomainsPath,
            RoleAccountsPath = RoleAccountsPath,
            FreeProvidersPath = FreeProvidersPath,
            B2CProvidersPath = B2CProvidersPath,
            SmtpRulesPath = SmtpRulesPath,
            UseBuiltinSmtpRules = !DisableBuiltinSmtpRules.IsPresent
        };
        if (!string.IsNullOrWhiteSpace(SmtpProxyHost)) {
            options.SmtpProxy = new EmailSmtpProxyOptions {
                Host = SmtpProxyHost,
                Port = SmtpProxyPort,
                Username = SmtpProxyUsername,
                Password = SmtpProxyPassword
            };
        }

        await _healthCheck.VerifyEmailAddress(EmailAddress, options, CancelToken);
        WriteObject(_healthCheck.EmailAddressValidationAnalysis);
        if (IsExportRequested()) { await ExportNotImplementedAsync(); }
    }
}
