using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Providers.Email;
using MimeKit;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Validates email address syntax, DNS readiness, and optional SMTP/HTTP probes.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public sealed partial class EmailAddressValidationAnalysis {
    private static readonly string[] CommonProviderDomains = new[] {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "protonmail.com",
        "proton.me",
        "icloud.com",
        "yandex.com",
        "aol.com",
        "gmx.com",
        "zoho.com",
        "mail.com",
        "fastmail.com"
    };
    private static readonly HashSet<string> YahooDomains = new(StringComparer.OrdinalIgnoreCase) {
        "yahoo.com",
        "yahoo.co.uk",
        "yahoo.fr",
        "yahoo.de",
        "yahoo.es",
        "yahoo.it",
        "yahoo.com.br",
        "yahoo.com.ar",
        "yahoo.com.mx",
        "yahoo.co.in",
        "yahoo.co.jp",
        "ymail.com",
        "rocketmail.com"
    };
    private static readonly HashSet<string> MicrosoftConsumerDomains = new(StringComparer.OrdinalIgnoreCase) {
        "outlook.com",
        "outlook.co.uk",
        "hotmail.com",
        "hotmail.co.uk",
        "hotmail.fr",
        "live.com",
        "msn.com"
    };
    private static readonly HashSet<string> ProtonDomains = new(StringComparer.OrdinalIgnoreCase) {
        "proton.me",
        "protonmail.com",
        "protonmail.ch",
        "pm.me",
        "passmail.net"
    };
    private const string YahooSignupPage = "https://login.yahoo.com/account/create?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login";
    private const string YahooSignupApi = "https://login.yahoo.com/account/module/create?validateField=yid";
    private const string YahooUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private const string ProtonAvailabilityApiV4 = "https://account.proton.me/api/core/v4/users/available";
    private const string ProtonAvailabilityApi = "https://account.proton.me/api/users/available";
    private const string ProtonAvailabilityLegacyApi = "https://account.protonmail.com/api/users/available";
    private const string ProtonUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
    private const int MaxSuggestionDistance = 2;
    private const int MaxSmtpResponseLines = 50;
    private const int SmtpStatusCodeLength = 3;
    private const int TooManyRequestsStatusCode = 429;
    /// <summary>DNS configuration used for lookups.</summary>
    public DnsConfiguration? DnsConfiguration { get; set; }

    /// <summary>HTTP client factory used for external lookups.</summary>
    public IHttpClientFactory? HttpClientFactory { get; set; }

    /// <summary>Original input email address.</summary>
    public string Input { get; private set; } = string.Empty;

    /// <summary>Syntax details.</summary>
    public EmailAddressSyntaxDetails Syntax { get; private set; } = new();

    /// <summary>MX lookup details.</summary>
    public EmailAddressMxDetails Mx { get; private set; } = new();

    /// <summary>SMTP probe details.</summary>
    public EmailAddressSmtpDetails Smtp { get; private set; } = new();

    /// <summary>Miscellaneous classification details.</summary>
    public EmailAddressMiscDetails Misc { get; private set; } = new();

    /// <summary>Reachability confidence.</summary>
    public EmailReachabilityStatus IsReachable { get; private set; } = EmailReachabilityStatus.Unknown;

    /// <summary>Timing details.</summary>
    public EmailAddressValidationDebug? Debug { get; private set; }

    /// <summary>
    /// Runs validation for the specified email address.
    /// </summary>
    public async Task AnalyzeAsync(string emailAddress, EmailAddressValidationOptions? options, InternalLogger logger, CancellationToken cancellationToken = default) {
        if (emailAddress == null) {
            throw new ArgumentNullException(nameof(emailAddress));
        }
        options ??= new EmailAddressValidationOptions();
        var start = DateTimeOffset.UtcNow;
        Input = emailAddress;
        Syntax = new EmailAddressSyntaxDetails { Address = emailAddress };
        Mx = new EmailAddressMxDetails();
        Smtp = new EmailAddressSmtpDetails();
        Misc = new EmailAddressMiscDetails();

        Syntax = AnalyzeSyntax(emailAddress, options, logger);
        if (!Syntax.IsValidSyntax) {
            IsReachable = EmailReachabilityStatus.Invalid;
            Debug = BuildDebug(start);
            return;
        }

        var localPart = Syntax.Username ?? string.Empty;
        var domain = Syntax.Domain ?? string.Empty;
        Misc.IsRoleAccount = await EmailValidationData.IsRoleAccountAsync(NormalizeRoleLocalPart(localPart), options.RoleAccountsPath, cancellationToken).ConfigureAwait(false);
        Misc.IsDisposable = await EmailValidationData.IsDisposableDomainAsync(domain, options.DisposableDomainsPath, cancellationToken).ConfigureAwait(false);
        if (options.CheckFreeProvider) {
            Misc.IsFreeProvider = await EmailValidationData.IsFreeProviderAsync(domain, options.FreeProvidersPath, cancellationToken).ConfigureAwait(false);
        }
        Misc.IsB2C = await EmailValidationData.IsB2CProviderAsync(domain, options.B2CProvidersPath, cancellationToken).ConfigureAwait(false);
        if (!Misc.IsB2C && options.CheckFreeProvider && options.TreatFreeProvidersAsB2C) {
            Misc.IsB2C = Misc.IsFreeProvider;
        }

        if (options.CheckMx) {
            await AnalyzeMxAsync(domain, logger, cancellationToken);
        }

        if (Mx.Records.Count > 0) {
            var match = MailProviderKindDetector.DetectFromMxHosts(Mx.Records);
            Misc.ProviderKind = match.Provider;
            Misc.ProviderScore = match.Score;
            if (match.Evidence.Count > 0) {
                Misc.ProviderEvidence = match.Evidence.ToList();
            }
        }

        if (options.CheckSmtp) {
            var allowSmtp = !options.CheckMx || (Mx.AcceptsMail && !Mx.HasNullMx);
            if (allowSmtp) {
                EmailSmtpProviderPolicy? providerPolicy = null;
                if (options.ApplyProviderPolicies && Misc.ProviderKind != MailProviderKind.Unknown) {
                    providerPolicy = EmailSmtpProviderPolicyResolver.Resolve(Misc.ProviderKind, options);
                }

                bool smtpResolved = false;
                if (options.EnableProviderWebChecks) {
                    smtpResolved = await TryProviderWebCheckAsync(emailAddress, domain, options, logger, cancellationToken);
                }
                if (!smtpResolved) {
                    await AnalyzeSmtpAsync(emailAddress, domain, options, providerPolicy, logger, cancellationToken);
                }
            }
        }

        if (options.CheckGravatar) {
            Misc.GravatarUrl = await TryResolveGravatarAsync(Syntax.NormalizedEmail, options, logger, cancellationToken);
        }

        if (options.CheckHaveIBeenPwned && !string.IsNullOrWhiteSpace(options.HaveIBeenPwnedApiKey)) {
            Misc.HaveIBeenPwned = await TryCheckHaveIBeenPwnedAsync(Syntax.NormalizedEmail, options, logger, cancellationToken);
        }

        IsReachable = ComputeReachability(Syntax, Mx, Smtp, Misc);
        Debug = BuildDebug(start);
    }

    private static EmailAddressValidationDebug BuildDebug(DateTimeOffset start) {
        var end = DateTimeOffset.UtcNow;
        return new EmailAddressValidationDebug {
            StartTime = start,
            EndTime = end,
            Duration = end - start
        };
    }

    private static EmailReachabilityStatus ComputeReachability(EmailAddressSyntaxDetails syntax, EmailAddressMxDetails mx, EmailAddressSmtpDetails smtp, EmailAddressMiscDetails misc) {
        if (!syntax.IsValidSyntax) {
            return EmailReachabilityStatus.Invalid;
        }
        if (mx.Checked && (!mx.AcceptsMail || mx.HasNullMx)) {
            return EmailReachabilityStatus.Invalid;
        }
        if (smtp.Checked) {
            if (smtp.IsDisabled) {
                return EmailReachabilityStatus.Invalid;
            }
            if (smtp.IsPermanentFailure && !smtp.IsDeliverable) {
                return EmailReachabilityStatus.Invalid;
            }
            if (smtp.IsDeliverable) {
                if (smtp.HasFullInbox || smtp.IsCatchAll || misc.IsDisposable || misc.IsRoleAccount) {
                    return EmailReachabilityStatus.Risky;
                }
                return EmailReachabilityStatus.Safe;
            }
            if (smtp.HasFullInbox || smtp.IsCatchAll) {
                return EmailReachabilityStatus.Risky;
            }
        }
        if (misc.IsDisposable || misc.IsRoleAccount) {
            return EmailReachabilityStatus.Risky;
        }
        return EmailReachabilityStatus.Unknown;
    }

    private static EmailAddressSyntaxDetails AnalyzeSyntax(string? emailAddress, EmailAddressValidationOptions options, InternalLogger logger) {
        var result = new EmailAddressSyntaxDetails { Address = emailAddress };
        if (string.IsNullOrWhiteSpace(emailAddress)) {
            result.IsValidSyntax = false;
            result.Error = "Email address is empty.";
            return result;
        }

        var trimmed = emailAddress!.Trim();
        if (ContainsCrLf(trimmed)) {
            result.IsValidSyntax = false;
            result.Error = "Email address contains invalid characters.";
            return result;
        }
        if (trimmed.IndexOf('<') >= 0 || trimmed.IndexOf('>') >= 0) {
            result.IsValidSyntax = false;
            result.Error = "Display names are not allowed in this validator.";
            return result;
        }

        if (!MailboxAddress.TryParse(trimmed, out var mailbox)) {
            result.IsValidSyntax = false;
            result.Error = "Invalid email syntax.";
            return result;
        }
        if (mailbox == null) {
            result.IsValidSyntax = false;
            result.Error = "Invalid email syntax.";
            return result;
        }

        if (!string.IsNullOrWhiteSpace(mailbox.Name)) {
            result.IsValidSyntax = false;
            result.Error = "Display names are not allowed in this validator.";
            return result;
        }

        var address = mailbox.Address;
        var at = address.LastIndexOf('@');
        if (at < 1 || at == address.Length - 1) {
            result.IsValidSyntax = false;
            result.Error = "Missing local part or domain.";
            return result;
        }

        var local = address.Substring(0, at);
        var domain = address.Substring(at + 1);

        if (!options.AllowInternational && ContainsNonAscii(local)) {
            result.IsValidSyntax = false;
            result.Error = "International local parts are not allowed.";
            return result;
        }

        if (!options.AllowTopLevelDomains && domain.IndexOf('.') < 0) {
            result.IsValidSyntax = false;
            result.Error = "Top-level-only domains are not allowed.";
            return result;
        }

        string asciiDomain;
        try {
            asciiDomain = DomainHelper.ValidateIdn(domain);
        } catch (ArgumentException ex) {
            logger.WriteVerbose("Invalid domain in email address: {0}", ex.Message);
            result.IsValidSyntax = false;
            result.Error = "Invalid domain.";
            return result;
        }

        var normalized = $"{local}@{asciiDomain}";
        result.IsValidSyntax = true;
        result.Address = address;
        result.Username = local;
        result.Domain = asciiDomain;
        result.NormalizedEmail = normalized;
        result.Suggestion = TrySuggestDomain(local, asciiDomain);
        return result;
    }

    private static string? TrySuggestDomain(string localPart, string domain) {
        if (string.IsNullOrWhiteSpace(localPart) || string.IsNullOrWhiteSpace(domain)) {
            return null;
        }

        if (CommonProviderDomains.Any(provider => domain.Equals(provider, StringComparison.OrdinalIgnoreCase))) {
            return null;
        }

        string? best = null;
        int bestDistance = int.MaxValue;
        foreach (var provider in CommonProviderDomains) {
            if (Math.Abs(domain.Length - provider.Length) > MaxSuggestionDistance) {
                continue;
            }
            var distance = ComputeLevenshteinDistance(domain, provider);
            if (distance < bestDistance) {
                bestDistance = distance;
                best = provider;
                if (bestDistance == 0) {
                    break;
                }
            }
        }

        if (best == null || bestDistance > MaxSuggestionDistance) {
            return null;
        }

        return $"{localPart}@{best}";
    }

    /// <summary>Computes the Levenshtein distance between two strings.</summary>
    private static int ComputeLevenshteinDistance(string source, string target) {
        if (string.IsNullOrEmpty(source)) {
            return target?.Length ?? 0;
        }
        if (string.IsNullOrEmpty(target)) {
            return source.Length;
        }

        var sourceLength = source.Length;
        var targetLength = target.Length;
        var previous = new int[targetLength + 1];
        var current = new int[targetLength + 1];

        for (int j = 0; j <= targetLength; j++) {
            previous[j] = j;
        }

        for (int i = 1; i <= sourceLength; i++) {
            current[0] = i;
            for (int j = 1; j <= targetLength; j++) {
                int cost = source[i - 1] == target[j - 1] ? 0 : 1;
                current[j] = Math.Min(
                    Math.Min(current[j - 1] + 1, previous[j] + 1),
                    previous[j - 1] + cost
                );
            }

            var temp = previous;
            previous = current;
            current = temp;
        }

        return previous[targetLength];
    }

    private async Task AnalyzeMxAsync(string domain, InternalLogger logger, CancellationToken cancellationToken) {
        Mx.Checked = true;
        try {
            var dns = DnsConfiguration ?? new DnsConfiguration();
            var mxRecords = await dns.QueryDNS(domain, DnsRecordType.MX, cancellationToken: cancellationToken);
            var parsed = ParseMxRecords(mxRecords);
            var ordered = parsed
                .Where(p => !p.IsNull)
                .OrderBy(p => p.Priority)
                .ThenBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ToList();
            Mx.Records = ordered.Select(p => p.Host).ToList();
            if (ordered.Count > 0) {
                var primary = ordered.First();
                Mx.PrimaryHost = primary.Host;
                Mx.PrimaryPriority = primary.Priority;
            }

            if (parsed.Any(p => p.IsNull)) {
                Mx.HasNullMx = true;
                Mx.AcceptsMail = false;
                return;
            }

            if (ordered.Count > 0) {
                Mx.AcceptsMail = true;
                return;
            }

            var aRecords = await dns.QueryDNS(domain, DnsRecordType.A, cancellationToken: cancellationToken);
            var aaaaRecords = await dns.QueryDNS(domain, DnsRecordType.AAAA, cancellationToken: cancellationToken);
            var hasApex = (aRecords?.Length ?? 0) > 0 || (aaaaRecords?.Length ?? 0) > 0;
            Mx.AcceptsMail = hasApex;
            Mx.UsedApexFallback = hasApex;
            if (hasApex) {
                Mx.PrimaryHost = domain;
            }
        } catch (Exception ex) {
            Mx.Error = ex.Message;
            logger.WriteVerbose("MX validation failed: {0}", ex.Message);
        }
    }

    private async Task AnalyzeSmtpAsync(string emailAddress, string domain, EmailAddressValidationOptions options, EmailSmtpProviderPolicy? providerPolicy, InternalLogger logger, CancellationToken cancellationToken) {
        Smtp.Checked = true;
        var candidates = BuildSmtpCandidates(domain);
        if (candidates.Count == 0) {
            Smtp.Error = "No SMTP host available.";
            return;
        }

        var smtpPort = providerPolicy?.SmtpPortOverride ?? options.SmtpPort;
        var smtpTimeout = providerPolicy?.SmtpTimeoutOverride ?? options.SmtpTimeout;
        var probeDelay = options.SmtpProbeDelay < TimeSpan.Zero ? TimeSpan.Zero : options.SmtpProbeDelay;
        var enableCatchAll = options.CheckCatchAll && !(providerPolicy?.DisableCatchAll ?? false);
        if (options.DisableCatchAllForB2C && Misc.IsB2C) {
            enableCatchAll = false;
        }
        var ruleMatch = await EmailSmtpRuleResolver.ResolveAsync(domain, Mx.Records, options.SmtpRulesPath, options.UseBuiltinSmtpRules, cancellationToken).ConfigureAwait(false);
        if (ruleMatch != null) {
            if (ruleMatch.DisableCatchAll.HasValue) {
                enableCatchAll = !ruleMatch.DisableCatchAll.Value;
            }
            if (ruleMatch.SmtpTimeoutSeconds.HasValue) {
                var ruleTimeout = TimeSpan.FromSeconds(ruleMatch.SmtpTimeoutSeconds.Value);
                if (ruleTimeout > smtpTimeout) {
                    smtpTimeout = ruleTimeout;
                }
            }
            if (ruleMatch.SmtpPortOverride.HasValue) {
                smtpPort = ruleMatch.SmtpPortOverride.Value;
            }
        }
        var maxHosts = options.SmtpMaxHosts < 1 ? 1 : options.SmtpMaxHosts;
        int attempted = 0;
        foreach (var candidate in candidates) {
            if (attempted >= maxHosts) {
                break;
            }
            attempted++;
            if (attempted > 1 && probeDelay > TimeSpan.Zero) {
                await Task.Delay(probeDelay, cancellationToken);
            }
            ResetSmtpAttemptState();
            Smtp.AttemptedHosts.Add(candidate);
            bool completed = await TryAnalyzeSmtpHostAsync(emailAddress, domain, candidate, smtpPort, smtpTimeout, enableCatchAll, options, logger, cancellationToken);
            if (completed) {
                return;
            }
            if (!string.IsNullOrWhiteSpace(Smtp.Error)) {
                Smtp.AttemptErrors[candidate] = Smtp.Error ?? string.Empty;
            }
        }
    }

    private async Task<bool> TryAnalyzeSmtpHostAsync(string emailAddress, string domain, string host, int smtpPort, TimeSpan smtpTimeout, bool enableCatchAll, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        var retryCount = options.SmtpRetryCount < 0 ? 0 : options.SmtpRetryCount;
        var retryDelay = options.SmtpRetryDelay < TimeSpan.Zero ? TimeSpan.Zero : options.SmtpRetryDelay;

        for (var attempt = 0; attempt <= retryCount; attempt++) {
            ResetSmtpAttemptState();
            bool completed = await TryAnalyzeSmtpHostOnceAsync(emailAddress, domain, host, smtpPort, smtpTimeout, enableCatchAll, options, logger, cancellationToken);
            if (!completed) {
                if (attempt < retryCount && retryDelay > TimeSpan.Zero) {
                    await Task.Delay(retryDelay, cancellationToken);
                }
                continue;
            }
            if (Smtp.IsPermanentFailure && !Smtp.IsGreylisted) {
                return true;
            }
            if (Smtp.IsTemporaryFailure || Smtp.IsGreylisted) {
                if (attempt < retryCount && retryDelay > TimeSpan.Zero) {
                    await Task.Delay(retryDelay, cancellationToken);
                }
                continue;
            }
            return true;
        }

        return !Smtp.IsTemporaryFailure && !Smtp.IsGreylisted && Smtp.CanConnectSmtp;
    }

    private async Task<bool> TryProviderWebCheckAsync(string emailAddress, string domain, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(domain)) {
            return false;
        }

        if (IsYahooDomain(domain)) {
            var exists = await TryCheckYahooAccountAsync(emailAddress, options, logger, cancellationToken);
            if (exists.HasValue) {
                Smtp.Checked = true;
                Smtp.UsedProviderWebCheck = true;
                Smtp.VerificationMethod = "ProviderWeb";
                Smtp.VerificationDetail = "Yahoo";
                Smtp.CanConnectSmtp = true;
                Smtp.IsDeliverable = exists.Value;
                Smtp.IsPermanentFailure = !exists.Value;
                return true;
            }
            logger.WriteVerbose("Provider web check failed for Yahoo.");
        }

        if (IsMicrosoftConsumerDomain(domain)) {
            var exists = await TryCheckMicrosoftAccountAsync(emailAddress, options, logger, cancellationToken);
            if (exists.HasValue) {
                Smtp.Checked = true;
                Smtp.UsedProviderWebCheck = true;
                Smtp.VerificationMethod = "ProviderWeb";
                Smtp.VerificationDetail = "Microsoft";
                Smtp.CanConnectSmtp = true;
                Smtp.IsDeliverable = exists.Value;
                Smtp.IsPermanentFailure = !exists.Value;
                return true;
            }
            logger.WriteVerbose("Provider web check failed for Microsoft consumer domains.");
        }

        if (IsProtonDomain(domain)) {
            if (string.IsNullOrWhiteSpace(options.ProtonAuthCookie) || string.IsNullOrWhiteSpace(options.ProtonUid)) {
                logger.WriteVerbose("Provider web check skipped for Proton (missing auth cookie or uid).");
            } else {
                var exists = await TryCheckProtonAccountAsync(emailAddress, options, logger, cancellationToken);
                if (exists.HasValue) {
                    Smtp.Checked = true;
                    Smtp.UsedProviderWebCheck = true;
                    Smtp.VerificationMethod = "ProviderWeb";
                    Smtp.VerificationDetail = "Proton";
                    Smtp.CanConnectSmtp = true;
                    Smtp.IsDeliverable = exists.Value;
                    Smtp.IsPermanentFailure = !exists.Value;
                    return true;
                }
                logger.WriteVerbose("Provider web check failed for Proton domains.");
            }
        }

        return false;
    }

}
