using DomainDetective.Providers.Email;
using System;
using System.Collections.Generic;

namespace DomainDetective;

/// <summary>
/// Options controlling email address validation behavior.
/// </summary>
public sealed class EmailAddressValidationOptions {
    /// <summary>Allow international characters in the local part.</summary>
    public bool AllowInternational { get; set; }

    /// <summary>Allow top-level-only domains (no dot).</summary>
    public bool AllowTopLevelDomains { get; set; }

    /// <summary>Enable MX/A/AAAA validation.</summary>
    public bool CheckMx { get; set; } = true;

    /// <summary>Enable SMTP probe for deliverability.</summary>
    public bool CheckSmtp { get; set; }

    /// <summary>Attempt catch-all detection when SMTP probing.</summary>
    public bool CheckCatchAll { get; set; }

    /// <summary>Disable catch-all probing for known B2C providers.</summary>
    public bool DisableCatchAllForB2C { get; set; } = true;

    /// <summary>Enable provider-specific web checks when available.</summary>
    public bool EnableProviderWebChecks { get; set; }

    /// <summary>Proton API auth cookie value (AUTH-&lt;uid&gt;).</summary>
    public string? ProtonAuthCookie { get; set; }

    /// <summary>Proton API uid value (x-pm-uid).</summary>
    public string? ProtonUid { get; set; }

    /// <summary>SMTP port to probe.</summary>
    public int SmtpPort { get; set; } = 25;

    /// <summary>Timeout for SMTP probing.</summary>
    public TimeSpan SmtpTimeout { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Maximum number of SMTP hosts to try (from MX records).</summary>
    public int SmtpMaxHosts { get; set; } = 1;

    /// <summary>Number of retries for SMTP verification on temporary failures.</summary>
    public int SmtpRetryCount { get; set; } = 1;

    /// <summary>Delay between SMTP retries.</summary>
    public TimeSpan SmtpRetryDelay { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>EHLO/HELO name to present during SMTP probing.</summary>
    public string? SmtpHelloName { get; set; }

    /// <summary>MAIL FROM address used during SMTP probing.</summary>
    public string? SmtpFromAddress { get; set; }

    /// <summary>Optional SOCKS5 proxy settings for SMTP probing.</summary>
    public EmailSmtpProxyOptions? SmtpProxy { get; set; }

    /// <summary>Check for Gravatar existence.</summary>
    public bool CheckGravatar { get; set; }

    /// <summary>Check Have I Been Pwned for breach status.</summary>
    public bool CheckHaveIBeenPwned { get; set; }

    /// <summary>API key for Have I Been Pwned.</summary>
    public string? HaveIBeenPwnedApiKey { get; set; }

    /// <summary>Base URL for Have I Been Pwned API (must end with '/').</summary>
    public string HaveIBeenPwnedBaseUrl { get; set; } = "https://haveibeenpwned.com/api/v3/";

    /// <summary>Include free-provider classification.</summary>
    public bool CheckFreeProvider { get; set; } = true;

    /// <summary>Apply provider-specific SMTP policies when available.</summary>
    public bool ApplyProviderPolicies { get; set; } = true;

    /// <summary>Optional per-provider SMTP policy overrides.</summary>
    public IDictionary<MailProviderKind, EmailSmtpProviderPolicy>? ProviderPolicies { get; set; }

    /// <summary>Timeout for HTTP lookups (Gravatar/HIBP).</summary>
    public TimeSpan HttpTimeout { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>Optional path to a disposable domain list (overrides built-in).</summary>
    public string? DisposableDomainsPath { get; set; }

    /// <summary>Optional path to a role account list (overrides built-in).</summary>
    public string? RoleAccountsPath { get; set; }

    /// <summary>Optional path to a free provider list (overrides built-in).</summary>
    public string? FreeProvidersPath { get; set; }

    /// <summary>Optional path to a B2C provider list (overrides built-in).</summary>
    public string? B2CProvidersPath { get; set; }

    /// <summary>Optional path to SMTP rules JSON.</summary>
    public string? SmtpRulesPath { get; set; }

    /// <summary>Use built-in SMTP rules when no custom rules path is provided.</summary>
    public bool UseBuiltinSmtpRules { get; set; } = true;
}
