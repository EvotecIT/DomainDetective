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
public sealed class EmailAddressValidationAnalysis {
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
    private const string MicrosoftCredentialTypeUrl = "https://login.microsoftonline.com/common/GetCredentialType";
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

        foreach (var provider in CommonProviderDomains) {
            if (domain.Equals(provider, StringComparison.OrdinalIgnoreCase)) {
                return null;
            }
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

    private static bool IsYahooDomain(string domain) {
        var clean = domain.Trim().Trim('.').ToLowerInvariant();
        return YahooDomains.Contains(clean);
    }

    private static bool IsMicrosoftConsumerDomain(string domain) {
        var clean = domain.Trim().Trim('.').ToLowerInvariant();
        return MicrosoftConsumerDomains.Contains(clean);
    }

    private static bool IsProtonDomain(string domain) {
        var clean = domain.Trim().Trim('.').ToLowerInvariant();
        return ProtonDomains.Contains(clean);
    }

    private async Task<bool?> TryCheckYahooAccountAsync(string emailAddress, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        var at = emailAddress.IndexOf('@');
        if (at <= 0) {
            return null;
        }
        var username = emailAddress.Substring(0, at).Trim();
        if (username.Length == 0) {
            return null;
        }

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);

            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var getRequest = new HttpRequestMessage(HttpMethod.Get, YahooSignupPage);
            getRequest.Headers.UserAgent.ParseAdd(YahooUserAgent);
            using var getResponse = await client.SendAsync(getRequest, timeoutCts.Token).ConfigureAwait(false);
            if (!getResponse.IsSuccessStatusCode) {
                return null;
            }

            if (!getResponse.Headers.TryGetValues("Set-Cookie", out var cookieValues)) {
                return null;
            }

            var cookiePairs = new List<string>();
            foreach (var cookie in cookieValues) {
                if (string.IsNullOrWhiteSpace(cookie)) {
                    continue;
                }
                var parts = cookie.Split(new[] { ';' }, 2);
                var pair = parts.Length > 0 ? parts[0].Trim() : string.Empty;
                if (pair.Length > 0) {
                    cookiePairs.Add(pair);
                }
            }
            if (cookiePairs.Count == 0) {
                return null;
            }
            var cookies = string.Join("; ", cookiePairs);
            var getBody = await getResponse.Content.ReadAsStringAsync().ConfigureAwait(false);

            var acrumbMatch = Regex.Match(cookies, "s=(?<acrumb>[^;]*)&d", RegexOptions.IgnoreCase, RegexTimeout);
            if (!acrumbMatch.Success) {
                return null;
            }
            var acrumb = acrumbMatch.Groups["acrumb"].Value;

            var sessionMatch = Regex.Match(getBody, "name=\"sessionIndex\"\\s+value=\"(?<sessionIndex>[^\"]+)\"", RegexOptions.IgnoreCase, RegexTimeout);
            if (!sessionMatch.Success) {
                return null;
            }
            var sessionIndex = sessionMatch.Groups["sessionIndex"].Value;

            var form = new Dictionary<string, string> {
                { "acrumb", acrumb },
                { "sessionIndex", sessionIndex },
                { "specId", "yidReg" },
                { "userId", username }
            };
            using var postRequest = new HttpRequestMessage(HttpMethod.Post, YahooSignupApi) {
                Content = new FormUrlEncodedContent(form)
            };
            postRequest.Headers.UserAgent.ParseAdd(YahooUserAgent);
            postRequest.Headers.TryAddWithoutValidation("Origin", "https://login.yahoo.com");
            postRequest.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
            postRequest.Headers.TryAddWithoutValidation("Accept", "*/*");
            postRequest.Headers.TryAddWithoutValidation("Referer", YahooSignupPage);
            postRequest.Headers.TryAddWithoutValidation("Accept-Language", "en-US,en;q=0.8");
            postRequest.Headers.TryAddWithoutValidation("Cookie", cookies);

            using var postResponse = await client.SendAsync(postRequest, timeoutCts.Token).ConfigureAwait(false);
            if (!postResponse.IsSuccessStatusCode) {
                return null;
            }

            var json = await postResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            var response = JsonSerializer.Deserialize<YahooFormResponse>(json, new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true
            });
            if (response?.Errors == null) {
                return null;
            }

            foreach (var error in response.Errors) {
                if (!string.Equals(error.Name, "userId", StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }
                if (string.Equals(error.Error, "IDENTIFIER_NOT_AVAILABLE", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(error.Error, "IDENTIFIER_EXISTS", StringComparison.OrdinalIgnoreCase)) {
                    return true;
                }
            }
            return false;
        } catch (Exception ex) {
            logger.WriteVerbose("Yahoo provider check failed: {0}", ex.Message);
            return null;
        }
    }

    private async Task<bool?> TryCheckMicrosoftAccountAsync(string emailAddress, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);

            var payload = new Dictionary<string, object> {
                { "Username", emailAddress },
                { "isOtherIdpSupported", true },
                { "checkPhones", false },
                { "isRemoteNGCSupported", true },
                { "isCookieBannerShown", false },
                { "isFidoSupported", true },
                { "forceotclogin", false },
                { "isExternalFederationDisallowed", false },
                { "isRemoteConnectSupported", false },
                { "federationFlags", 0 },
                { "isSignup", false },
                { "flowToken", string.Empty },
                { "isAccessPassSupported", true }
            };

            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Post, MicrosoftCredentialTypeUrl) {
                Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
            };
            request.Headers.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            using var response = await client.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return null;
            }

            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var result = JsonSerializer.Deserialize<MicrosoftCredentialTypeResponse>(json, new JsonSerializerOptions {
                PropertyNameCaseInsensitive = true
            });
            if (result == null || !result.IfExistsResult.HasValue) {
                return null;
            }

            return result.IfExistsResult.Value switch {
                0 => true,
                1 => false,
                5 => true,
                6 => true,
                _ => null
            };
        } catch (Exception ex) {
            logger.WriteVerbose("Microsoft provider check failed: {0}", ex.Message);
            return null;
        }
    }

    private async Task<bool?> TryCheckProtonAccountAsync(string emailAddress, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        var at = emailAddress.IndexOf('@');
        if (at <= 0) {
            return null;
        }
        var username = emailAddress.Substring(0, at).Trim();
        if (username.Length == 0) {
            return null;
        }

        if (!TryBuildProtonAuthHeaders(options, out var cookieHeader, out var uidHeader)) {
            return null;
        }

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);

            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            var exists = await TryQueryProtonAvailabilityAsync(client, ProtonAvailabilityApiV4, username, emailAddress, cookieHeader, uidHeader, timeoutCts.Token).ConfigureAwait(false);
            if (!exists.HasValue) {
                exists = await TryQueryProtonAvailabilityAsync(client, ProtonAvailabilityApi, username, emailAddress, cookieHeader, uidHeader, timeoutCts.Token).ConfigureAwait(false);
            }
            if (!exists.HasValue) {
                exists = await TryQueryProtonAvailabilityAsync(client, ProtonAvailabilityLegacyApi, username, emailAddress, cookieHeader, uidHeader, timeoutCts.Token).ConfigureAwait(false);
            }
            return exists;
        } catch (Exception ex) {
            logger.WriteVerbose("Proton provider check failed: {0}", ex.Message);
            return null;
        }
    }

    private static bool TryBuildProtonAuthHeaders(EmailAddressValidationOptions options, out string cookieHeader, out string uidHeader) {
        cookieHeader = string.Empty;
        uidHeader = string.Empty;
        if (string.IsNullOrWhiteSpace(options.ProtonAuthCookie) || string.IsNullOrWhiteSpace(options.ProtonUid)) {
            return false;
        }

        uidHeader = (options.ProtonUid ?? string.Empty).Trim();
        var authCookie = (options.ProtonAuthCookie ?? string.Empty).Trim();
        if (authCookie.IndexOf("AUTH-", StringComparison.OrdinalIgnoreCase) >= 0 && authCookie.Contains("=")) {
            cookieHeader = authCookie;
        } else {
            cookieHeader = $"AUTH-{uidHeader}={authCookie}";
        }
        return true;
    }

    private static async Task<bool?> TryQueryProtonAvailabilityAsync(HttpClient client, string endpoint, string username, string emailAddress, string cookieHeader, string uidHeader, CancellationToken cancellationToken) {
        var payload = new Dictionary<string, string> {
            { "Name", username },
            { "Email", emailAddress }
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint) {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        ApplyProtonHeaders(request, cookieHeader, uidHeader);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.MethodNotAllowed) {
            return await TryQueryProtonAvailabilityGetAsync(client, endpoint, username, cookieHeader, uidHeader, cancellationToken).ConfigureAwait(false);
        }

        return await InterpretProtonAvailabilityResponseAsync(response).ConfigureAwait(false);
    }

    private static async Task<bool?> TryQueryProtonAvailabilityGetAsync(HttpClient client, string endpoint, string username, string cookieHeader, string uidHeader, CancellationToken cancellationToken) {
        var uri = $"{endpoint}?Name={Uri.EscapeDataString(username)}";
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        ApplyProtonHeaders(request, cookieHeader, uidHeader);
        using var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await InterpretProtonAvailabilityResponseAsync(response).ConfigureAwait(false);
    }

    private static void ApplyProtonHeaders(HttpRequestMessage request, string cookieHeader, string uidHeader) {
        request.Headers.UserAgent.ParseAdd(ProtonUserAgent);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
        request.Headers.TryAddWithoutValidation("x-pm-uid", uidHeader);
    }

    private static async Task<bool?> InterpretProtonAvailabilityResponseAsync(HttpResponseMessage response) {
        if (response.StatusCode == HttpStatusCode.Conflict) {
            return true;
        }
        if (response.StatusCode == HttpStatusCode.Unauthorized || response.StatusCode == HttpStatusCode.Forbidden || (int)response.StatusCode == TooManyRequestsStatusCode) {
            return null;
        }
        if (!response.IsSuccessStatusCode) {
            return null;
        }

        var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(json)) {
            return null;
        }

        var result = JsonSerializer.Deserialize<ProtonAvailabilityResponse>(json, new JsonSerializerOptions {
            PropertyNameCaseInsensitive = true
        });
        if (result == null) {
            return null;
        }
        if (result.Available.HasValue) {
            return !result.Available.Value;
        }
        if (result.Code.HasValue) {
            return result.Code.Value == 1000 ? false : (bool?)null;
        }
        return null;
    }

    private sealed class MicrosoftCredentialTypeResponse {
        public int? IfExistsResult { get; set; }
    }

    private sealed class ProtonAvailabilityResponse {
        public bool? Available { get; set; }
        public int? Code { get; set; }
        public string? Error { get; set; }
        public string? ErrorCode { get; set; }
        public string? Message { get; set; }
    }

    private sealed class YahooFormResponse {
        public YahooFormError[]? Errors { get; set; }
    }

    private sealed class YahooFormError {
        public string? Error { get; set; }
        public string? Name { get; set; }
    }

    private async Task<bool> TryAnalyzeSmtpHostOnceAsync(string emailAddress, string domain, string host, int smtpPort, TimeSpan smtpTimeout, bool enableCatchAll, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        Smtp.Host = host;
        Smtp.Port = smtpPort;
        Smtp.VerificationMethod = "Smtp";
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(smtpTimeout);

        StreamReader? reader = null;
        StreamWriter? writer = null;
        SslStream? sslStream = null;

        try {
            using var client = new TcpClient();
            var proxy = options.SmtpProxy;
            if (proxy?.IsConfigured == true) {
                Smtp.UsedProxy = true;
                Smtp.ProxyHost = proxy.Host;
                Smtp.ProxyPort = proxy.Port;
                await client.ConnectAsync(proxy.Host, proxy.Port).WaitWithCancellation(timeoutCts.Token);
            } else {
                await client.ConnectAsync(host, smtpPort).WaitWithCancellation(timeoutCts.Token);
            }
            using NetworkStream network = client.GetStream();
            if (proxy?.IsConfigured == true) {
                await EstablishSocks5TunnelAsync(network, host, smtpPort, proxy, timeoutCts.Token);
            }
            Stream activeStream = network;
            reader = CreateSmtpReader(activeStream);
            writer = CreateSmtpWriter(activeStream);
            bool tlsUpgraded = false;

            void ResetIo(Stream stream) {
                reader?.Dispose();
                writer?.Dispose();
                reader = CreateSmtpReader(stream);
                writer = CreateSmtpWriter(stream);
            }

            var banner = await ReadResponseAsync(reader, timeoutCts.Token);
            if (banner == null) {
                Smtp.Error = "No SMTP banner received.";
                return false;
            }

            Smtp.CanConnectSmtp = true;

            var helloName = string.IsNullOrWhiteSpace(options.SmtpHelloName)
                ? domain
                : options.SmtpHelloName!.Trim();
            if (ContainsCrLf(helloName) || ContainsCrLf(emailAddress)) {
                Smtp.Error = "SMTP command contains invalid characters.";
                return false;
            }
            var capabilities = await SendEhloAsync(writer, reader, helloName, timeoutCts.Token);
            var supportsStartTls = capabilities.Contains("STARTTLS");

            var fromAddress = BuildFromAddress(options.SmtpFromAddress, domain);
            if (ContainsCrLf(fromAddress)) {
                Smtp.Error = "SMTP command contains invalid characters.";
                return false;
            }
            (string? mailResp, string? rcptResp) = await SendMailRcptAsync(writer, reader, fromAddress, emailAddress, timeoutCts.Token);
            Smtp.MailFromResponse = mailResp;
            Smtp.MailFromStatusCode = ParseStatusCode(mailResp);
            Smtp.RcptToResponse = rcptResp;
            Smtp.RcptToStatusCode = ParseStatusCode(rcptResp);

            bool requireTls = ResponseRequiresStartTls(mailResp) || ResponseRequiresStartTls(rcptResp);
            if (requireTls && supportsStartTls && !tlsUpgraded) {
                var upgraded = await TryStartTlsAsync();
                if (upgraded) {
                    Smtp.RequiresStartTls = true;
                    tlsUpgraded = true;
                    ResetSmtpFlags();
                    capabilities = await SendEhloAsync(writer, reader, helloName, timeoutCts.Token);
                    supportsStartTls = capabilities.Contains("STARTTLS");
                    (mailResp, rcptResp) = await SendMailRcptAsync(writer, reader, fromAddress, emailAddress, timeoutCts.Token);
                    Smtp.MailFromResponse = mailResp;
                    Smtp.MailFromStatusCode = ParseStatusCode(mailResp);
                    Smtp.RcptToResponse = rcptResp;
                    Smtp.RcptToStatusCode = ParseStatusCode(rcptResp);
                } else {
                    Smtp.RequiresStartTls = true;
                    Smtp.Error ??= "STARTTLS required but negotiation failed.";
                }
            }

            InterpretSmtpResponse(rcptResp, Smtp, logger);

            if (enableCatchAll && !Smtp.RequiresStartTls && !string.IsNullOrWhiteSpace(domain)) {
                var randomLocal = $"dd-{Guid.NewGuid():N}";
                await writer.WriteLineAsync($"RCPT TO:<{randomLocal}@{domain}>").WaitWithCancellation(timeoutCts.Token);
                var catchResp = await ReadResponseAsync(reader, timeoutCts.Token);
                Smtp.CatchAllResponse = catchResp;
                if (IsPositiveResponse(catchResp)) {
                    Smtp.IsCatchAll = true;
                }
            }

            await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
            await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
            try {
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
            } catch (IOException) {
                // ignore disconnect after QUIT
            }

            async Task<bool> TryStartTlsAsync() {
                await writer.WriteLineAsync("STARTTLS").WaitWithCancellation(timeoutCts.Token);
                var startResp = await ReadResponseAsync(reader, timeoutCts.Token);
                if (!IsPositiveResponse(startResp)) {
                    return false;
                }
                sslStream = new SslStream(network, false, (_, _, _, errors) => {
                    if (errors == SslPolicyErrors.None) {
                        return true;
                    }
                    if (options.AllowInvalidSmtpCertificates) {
                        logger.WriteVerbose("SMTP TLS certificate validation bypassed: {0}", errors);
                        return true;
                    }
                    return false;
                });
                await sslStream.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
                activeStream = sslStream;
                ResetIo(activeStream);
                return true;
            }

            void ResetSmtpFlags() {
                Smtp.IsDeliverable = false;
                Smtp.HasFullInbox = false;
                Smtp.IsDisabled = false;
                Smtp.IsCatchAll = false;
                Smtp.IsTemporaryFailure = false;
                Smtp.IsPermanentFailure = false;
                Smtp.IsGreylisted = false;
            }

            return true;
        } catch (Exception ex) when (ex is IOException || ex is OperationCanceledException || ex is SocketException) {
            Smtp.Error = ex.Message;
            logger.WriteVerbose("SMTP probe failed: {0}", ex.Message);
            return false;
        } finally {
            reader?.Dispose();
            writer?.Dispose();
            sslStream?.Dispose();
        }
    }

    private void ResetSmtpAttemptState() {
        Smtp.CanConnectSmtp = false;
        Smtp.IsDeliverable = false;
        Smtp.HasFullInbox = false;
        Smtp.IsDisabled = false;
        Smtp.IsCatchAll = false;
        Smtp.RequiresStartTls = false;
        Smtp.IsTemporaryFailure = false;
        Smtp.IsPermanentFailure = false;
        Smtp.IsGreylisted = false;
        Smtp.MailFromResponse = null;
        Smtp.RcptToResponse = null;
        Smtp.MailFromStatusCode = null;
        Smtp.RcptToStatusCode = null;
        Smtp.CatchAllResponse = null;
        Smtp.Error = null;
        Smtp.UsedProxy = false;
        Smtp.ProxyHost = null;
        Smtp.ProxyPort = null;
        Smtp.VerificationMethod = null;
        Smtp.VerificationDetail = null;
        Smtp.UsedProviderWebCheck = false;
    }

    /// <summary>Builds a prioritized list of SMTP hosts to probe.</summary>
    private List<string> BuildSmtpCandidates(string domain) {
        var candidates = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddCandidate(string? host) {
            if (string.IsNullOrWhiteSpace(host)) {
                return;
            }
            if (host == null) {
                return;
            }
            var normalized = host.Trim().Trim('.');
            if (normalized.Length == 0) {
                return;
            }
            if (seen.Add(normalized)) {
                candidates.Add(normalized);
            }
        }

        AddCandidate(Mx.PrimaryHost);
        foreach (var host in Mx.Records) {
            AddCandidate(host);
        }
        if (candidates.Count == 0) {
            AddCandidate(domain);
        }

        return candidates;
    }

    private static string BuildFromAddress(string? fromAddress, string domain) {
        var trimmed = fromAddress == null ? null : fromAddress.Trim();
        if (!string.IsNullOrWhiteSpace(trimmed)) {
            return trimmed ?? string.Empty;
        }
        if (!string.IsNullOrWhiteSpace(domain)) {
            return $"postmaster@{domain}";
        }
        return "postmaster@example.com";
    }

    private static void InterpretSmtpResponse(string? response, EmailAddressSmtpDetails smtp, InternalLogger logger) {
        if (string.IsNullOrWhiteSpace(response)) {
            return;
        }

        var code = ParseStatusCode(response);
        if (code >= 200 && code < 300) {
            smtp.IsDeliverable = true;
        }
        if (code >= 400 && code < 500) {
            smtp.IsTemporaryFailure = true;
        }
        if (code >= 500 && code < 600) {
            smtp.IsPermanentFailure = true;
        }

        if (ResponseRequiresStartTls(response)) {
            smtp.RequiresStartTls = true;
            smtp.IsDeliverable = false;
        }

        if (code == 452 || code == 552 || ContainsOrdinalIgnoreCase(response, "mailbox full") || ContainsOrdinalIgnoreCase(response, "over quota") || ContainsOrdinalIgnoreCase(response, "quota")) {
            smtp.HasFullInbox = true;
        }

        if (ContainsOrdinalIgnoreCase(response, "disabled") || ContainsOrdinalIgnoreCase(response, "inactive")) {
            smtp.IsDisabled = true;
        }

        if (code == 421 || code == 450 || code == 451 || ContainsOrdinalIgnoreCase(response, "greylist") || ContainsOrdinalIgnoreCase(response, "try again later") || ContainsOrdinalIgnoreCase(response, "temporar")) {
            smtp.IsGreylisted = true;
            smtp.IsTemporaryFailure = true;
        }

        if (code >= 500 && code < 600 && ContainsOrdinalIgnoreCase(response, "user unknown")) {
            logger.WriteVerbose("SMTP reported user unknown.");
        }
    }

    private static bool ResponseRequiresStartTls(string? response) {
        if (string.IsNullOrWhiteSpace(response)) {
            return false;
        }
        var code = ParseStatusCode(response);
        if (code == 530 || code == 538) {
            return true;
        }
        return ContainsOrdinalIgnoreCase(response, "starttls") || ContainsOrdinalIgnoreCase(response, "tls required");
    }

    private static bool ContainsOrdinalIgnoreCase(string? source, string value) {
        if (string.IsNullOrEmpty(source) || string.IsNullOrEmpty(value)) {
            return false;
        }
        return source.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool ContainsCrLf(string? value) {
        if (string.IsNullOrEmpty(value)) {
            return false;
        }
        return value.IndexOfAny(new[] { '\r', '\n' }) >= 0;
    }

    private static StreamReader CreateSmtpReader(Stream stream) {
        return new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
    }

    private static StreamWriter CreateSmtpWriter(Stream stream) {
        return new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true) { AutoFlush = true, NewLine = "\r\n" };
    }

    private static async Task<(string? MailResp, string? RcptResp)> SendMailRcptAsync(StreamWriter writer, StreamReader reader, string fromAddress, string emailAddress, CancellationToken token) {
        await writer.WriteLineAsync($"MAIL FROM:<{fromAddress}>").WaitWithCancellation(token);
        var mailResp = await ReadResponseAsync(reader, token);
        await writer.WriteLineAsync($"RCPT TO:<{emailAddress}>").WaitWithCancellation(token);
        var rcptResp = await ReadResponseAsync(reader, token);
        return (mailResp, rcptResp);
    }

    private static async Task<HashSet<string>> SendEhloAsync(StreamWriter writer, StreamReader reader, string helloName, CancellationToken token) {
        await writer.WriteLineAsync($"EHLO {helloName}").WaitWithCancellation(token);
        var lines = await ReadResponseLinesAsync(reader, token);
        var success = IsPositiveResponse(lines.LastOrDefault());
        if (!success) {
            await writer.WriteLineAsync($"HELO {helloName}").WaitWithCancellation(token);
            var helo = await ReadResponseAsync(reader, token);
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        }
        var capabilities = ParseEhloCapabilities(lines);
        return capabilities;
    }

    private static HashSet<string> ParseEhloCapabilities(IEnumerable<string> lines) {
        var caps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines) {
            if (!line.StartsWith("250", StringComparison.Ordinal)) {
                continue;
            }
            var payload = line.Length > 4 ? line.Substring(4).Trim() : string.Empty;
            if (string.IsNullOrWhiteSpace(payload)) {
                continue;
            }
            var token = payload.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(token)) {
                caps.Add(token);
            }
        }
        return caps;
    }

    private static int ParseStatusCode(string? response) {
        if (string.IsNullOrWhiteSpace(response)) {
            return -1;
        }
        var value = response ?? string.Empty;
        if (value.Length < SmtpStatusCodeLength) {
            return -1;
        }
        if (int.TryParse(value.Substring(0, SmtpStatusCodeLength), out var code)) {
            return code;
        }
        return -1;
    }

    private static bool IsPositiveResponse(string? response) {
        var code = ParseStatusCode(response);
        return code >= 200 && code < 300;
    }

    private static async Task<string?> ReadResponseAsync(StreamReader reader, CancellationToken token) {
        string? line = await reader.ReadLineAsync().WaitWithCancellation(token);
        if (line == null) {
            return null;
        }
        var code = line.Length >= SmtpStatusCodeLength ? line.Substring(0, SmtpStatusCodeLength) : string.Empty;
        var lastLine = line;
        int linesRead = 1;
        while (line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] == '-') {
            if (linesRead >= MaxSmtpResponseLines) {
                break;
            }
            line = await reader.ReadLineAsync().WaitWithCancellation(token);
            if (line == null) {
                break;
            }
            if (line.StartsWith(code, StringComparison.Ordinal)) {
                lastLine = line;
            } else {
                break;
            }
            linesRead++;
        }
        return lastLine;
    }

    private static async Task<List<string>> ReadResponseLinesAsync(StreamReader reader, CancellationToken token) {
        var lines = new List<string>();
        string? line = await reader.ReadLineAsync().WaitWithCancellation(token);
        if (line == null) {
            return lines;
        }
        lines.Add(line);
        var code = line.Length >= SmtpStatusCodeLength ? line.Substring(0, SmtpStatusCodeLength) : string.Empty;
        int linesRead = 1;
        while (line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] == '-') {
            if (linesRead >= MaxSmtpResponseLines) {
                break;
            }
            line = await reader.ReadLineAsync().WaitWithCancellation(token);
            if (line == null) {
                break;
            }
            lines.Add(line);
            if (line.StartsWith(code, StringComparison.Ordinal) && line.Length >= SmtpStatusCodeLength + 1 && line[SmtpStatusCodeLength] != '-') {
                break;
            }
            linesRead++;
        }
        return lines;
    }

    /// <summary>Establishes a SOCKS5 CONNECT tunnel to the target host and port.</summary>
    /// <para>Supports anonymous and username/password authentication.</para>
    private static async Task EstablishSocks5TunnelAsync(Stream stream, string host, int port, EmailSmtpProxyOptions proxy, CancellationToken token) {
        var methods = new List<byte> { 0x00 };
        var useAuth = !string.IsNullOrWhiteSpace(proxy.Username) || !string.IsNullOrWhiteSpace(proxy.Password);
        if (useAuth) {
            methods.Add(0x02);
        }

        var greeting = new byte[2 + methods.Count];
        greeting[0] = 0x05;
        greeting[1] = (byte)methods.Count;
        for (int i = 0; i < methods.Count; i++) {
            greeting[2 + i] = methods[i];
        }

        await stream.WriteAsync(greeting, 0, greeting.Length, token);
        var response = await ReadExactAsync(stream, 2, token);
        if (response[0] != 0x05) {
            throw new IOException("SOCKS5 proxy returned an invalid version.");
        }
        if (response[1] == 0xFF) {
            throw new IOException("SOCKS5 proxy rejected authentication methods.");
        }

        if (response[1] == 0x02) {
            var username = proxy.Username ?? string.Empty;
            var password = proxy.Password ?? string.Empty;
            byte[]? userBytes = null;
            byte[]? passBytes = null;
            byte[]? auth = null;
            try {
                userBytes = Encoding.ASCII.GetBytes(username);
                passBytes = Encoding.ASCII.GetBytes(password);
                if (userBytes.Length > 255 || passBytes.Length > 255) {
                    throw new IOException("SOCKS5 proxy credentials are too long.");
                }

                auth = new byte[3 + userBytes.Length + passBytes.Length];
                auth[0] = 0x01;
                auth[1] = (byte)userBytes.Length;
                Buffer.BlockCopy(userBytes, 0, auth, 2, userBytes.Length);
                auth[2 + userBytes.Length] = (byte)passBytes.Length;
                Buffer.BlockCopy(passBytes, 0, auth, 3 + userBytes.Length, passBytes.Length);

                await stream.WriteAsync(auth, 0, auth.Length, token);
                var authResp = await ReadExactAsync(stream, 2, token);
                if (authResp[1] != 0x00) {
                    throw new IOException("SOCKS5 proxy authentication failed.");
                }
            } finally {
                if (auth != null) {
                    Array.Clear(auth, 0, auth.Length);
                }
                if (userBytes != null) {
                    Array.Clear(userBytes, 0, userBytes.Length);
                }
                if (passBytes != null) {
                    Array.Clear(passBytes, 0, passBytes.Length);
                }
            }
        }

        byte atyp;
        byte[] addrBytes;
        if (IPAddress.TryParse(host, out var ip)) {
            if (ip.AddressFamily == AddressFamily.InterNetwork) {
                atyp = 0x01;
                addrBytes = ip.GetAddressBytes();
            } else if (ip.AddressFamily == AddressFamily.InterNetworkV6) {
                atyp = 0x04;
                addrBytes = ip.GetAddressBytes();
            } else {
                throw new IOException("Unsupported IP address family for SOCKS5.");
            }
        } else {
            var hostBytes = Encoding.ASCII.GetBytes(host);
            if (hostBytes.Length == 0 || hostBytes.Length > 255) {
                throw new IOException("SOCKS5 proxy host name is invalid.");
            }
            atyp = 0x03;
            addrBytes = new byte[hostBytes.Length + 1];
            addrBytes[0] = (byte)hostBytes.Length;
            Buffer.BlockCopy(hostBytes, 0, addrBytes, 1, hostBytes.Length);
        }

        var portBytes = new byte[2];
        portBytes[0] = (byte)(port >> 8);
        portBytes[1] = (byte)(port & 0xFF);

        var request = new byte[4 + addrBytes.Length + portBytes.Length];
        request[0] = 0x05;
        request[1] = 0x01;
        request[2] = 0x00;
        request[3] = atyp;
        Buffer.BlockCopy(addrBytes, 0, request, 4, addrBytes.Length);
        Buffer.BlockCopy(portBytes, 0, request, 4 + addrBytes.Length, portBytes.Length);

        await stream.WriteAsync(request, 0, request.Length, token);

        var header = await ReadExactAsync(stream, 4, token);
        if (header[0] != 0x05) {
            throw new IOException("SOCKS5 proxy returned an invalid connect response.");
        }
        if (header[1] != 0x00) {
            throw new IOException($"SOCKS5 proxy connection failed with code {header[1]}.");
        }

        int addrLen = header[3] switch {
            0x01 => 4,
            0x04 => 16,
            0x03 => (await ReadExactAsync(stream, 1, token))[0],
            _ => throw new IOException("SOCKS5 proxy returned an unknown address type.")
        };
        if (addrLen > 0) {
            await ReadExactAsync(stream, addrLen, token);
        }
        await ReadExactAsync(stream, 2, token);
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int count, CancellationToken token) {
        var buffer = new byte[count];
        int read = 0;
        while (read < count) {
            var bytesRead = await stream.ReadAsync(buffer, read, count - read, token);
            if (bytesRead == 0) {
                throw new IOException("Unexpected end of stream.");
            }
            read += bytesRead;
        }
        return buffer;
    }

    private static bool ContainsNonAscii(string value) {
        foreach (var ch in value) {
            if (ch > 127) {
                return true;
            }
        }
        return false;
    }

    private static string NormalizeRoleLocalPart(string localPart) {
        var normalized = localPart.Trim().Trim('.').ToLowerInvariant();
        var plus = normalized.IndexOf('+');
        if (plus > 0) {
            normalized = normalized.Substring(0, plus);
        }
        return normalized;
    }

    private static List<(int Priority, string Host, bool IsNull)> ParseMxRecords(IEnumerable<DnsAnswer> records) {
        var parsed = new List<(int, string, bool)>();
        foreach (var record in records ?? Array.Empty<DnsAnswer>()) {
            var data = record.Data ?? record.DataRaw;
            if (string.IsNullOrWhiteSpace(data)) {
                continue;
            }
            var parts = data.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) {
                continue;
            }
            int priority = 0;
            string host;
            if (parts.Length == 1) {
                host = parts[0].Trim().Trim('.');
            } else {
                int.TryParse(parts[0], out priority);
                host = parts[1].Trim().Trim('.');
            }
            if (string.IsNullOrWhiteSpace(host)) {
                continue;
            }
            bool isNull = host == ".";
            parsed.Add((priority, host, isNull));
        }
        return parsed;
    }

    private async Task<string?> TryResolveGravatarAsync(string? normalizedEmail, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(normalizedEmail)) {
            return null;
        }

        var normalizedValue = normalizedEmail ?? string.Empty;
        var normalized = normalizedValue.Trim().ToLowerInvariant();
        var hash = ComputeMd5(normalized);
        var url = $"https://www.gravatar.com/avatar/{hash}?d=404";

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);
            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Head, url);
            request.Headers.UserAgent.ParseAdd("DomainDetective");
            using var response = await client.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            if (response.IsSuccessStatusCode) {
                return url;
            }
            if ((int)response.StatusCode == 405) {
                using var getRequest = new HttpRequestMessage(HttpMethod.Get, url);
                getRequest.Headers.UserAgent.ParseAdd("DomainDetective");
                using var getResponse = await client.SendAsync(getRequest, timeoutCts.Token).ConfigureAwait(false);
                if (getResponse.IsSuccessStatusCode) {
                    return url;
                }
            }
            return null;
        } catch (Exception ex) {
            logger.WriteVerbose("Gravatar check failed: {0}", ex.Message);
            return null;
        }
    }

    private async Task<bool?> TryCheckHaveIBeenPwnedAsync(string? normalizedEmail, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        if (string.IsNullOrWhiteSpace(normalizedEmail) || string.IsNullOrWhiteSpace(options.HaveIBeenPwnedApiKey)) {
            return null;
        }

        var baseUrl = options.HaveIBeenPwnedBaseUrl;
        if (string.IsNullOrWhiteSpace(baseUrl)) {
            return null;
        }
        baseUrl = baseUrl.Trim();
        if (!baseUrl.EndsWith("/", StringComparison.Ordinal)) {
            baseUrl += "/";
        }

        var normalizedValue = normalizedEmail ?? string.Empty;
        var encoded = Uri.EscapeDataString(normalizedValue.Trim().ToLowerInvariant());
        var url = $"{baseUrl}breachedaccount/{encoded}?truncateResponse=true";

        try {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(options.HttpTimeout);
            var client = (HttpClientFactory ?? new SharedHttpClient()).CreateClient();
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.UserAgent.ParseAdd("DomainDetective");
            request.Headers.TryAddWithoutValidation("hibp-api-key", options.HaveIBeenPwnedApiKey!);
            using var response = await client.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
            if (response.IsSuccessStatusCode) {
                return true;
            }
            if ((int)response.StatusCode == 404) {
                return false;
            }
            return null;
        } catch (Exception ex) {
            logger.WriteVerbose("Have I Been Pwned check failed: {0}", ex.Message);
            return null;
        }
    }

    private static string ComputeMd5(string input) {
        using var md5 = MD5.Create();
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = md5.ComputeHash(bytes);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) {
            sb.Append(b.ToString("x2"));
        }
        return sb.ToString();
    }
}
