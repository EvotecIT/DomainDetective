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


public sealed partial class EmailAddressValidationAnalysis {
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

    private sealed class SmtpSessionIo : IDisposable {
        public Stream ActiveStream { get; private set; }
        public StreamReader Reader { get; private set; }
        public StreamWriter Writer { get; private set; }
        public SslStream? TlsStream { get; private set; }

        public SmtpSessionIo(NetworkStream network) {
            ActiveStream = network;
            Reader = CreateSmtpReader(network);
            Writer = CreateSmtpWriter(network);
        }

        public void UpgradeToTls(SslStream tlsStream) {
            Reader.Dispose();
            Writer.Dispose();
            TlsStream?.Dispose();
            TlsStream = tlsStream;
            ActiveStream = tlsStream;
            Reader = CreateSmtpReader(tlsStream);
            Writer = CreateSmtpWriter(tlsStream);
        }

        public void Dispose() {
            Reader.Dispose();
            Writer.Dispose();
            TlsStream?.Dispose();
        }
    }

    private async Task<bool> TryAnalyzeSmtpHostOnceAsync(string emailAddress, string domain, string host, int smtpPort, TimeSpan smtpTimeout, bool enableCatchAll, EmailAddressValidationOptions options, InternalLogger logger, CancellationToken cancellationToken) {
        Smtp.Host = host;
        Smtp.Port = smtpPort;
        Smtp.VerificationMethod = "Smtp";
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(smtpTimeout);

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
            using var sessionIo = new SmtpSessionIo(network);
            bool tlsUpgraded = false;
            bool startTlsRequired = false;
            bool startTlsFailed = false;

            var banner = await ReadResponseAsync(sessionIo.Reader, timeoutCts.Token);
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
            var capabilities = await SendEhloAsync(sessionIo.Writer, sessionIo.Reader, helloName, timeoutCts.Token);
            var supportsStartTls = capabilities.Contains("STARTTLS");

            var fromAddress = BuildFromAddress(options.SmtpFromAddress, domain);
            if (ContainsCrLf(fromAddress)) {
                Smtp.Error = "SMTP command contains invalid characters.";
                return false;
            }
            (string? mailResp, string? rcptResp) = await SendMailRcptAsync(sessionIo.Writer, sessionIo.Reader, fromAddress, emailAddress, timeoutCts.Token);
            Smtp.MailFromResponse = mailResp;
            Smtp.MailFromStatusCode = ParseStatusCode(mailResp);
            Smtp.RcptToResponse = rcptResp;
            Smtp.RcptToStatusCode = ParseStatusCode(rcptResp);

            bool requireTls = ResponseRequiresStartTls(mailResp) || ResponseRequiresStartTls(rcptResp);
            if (requireTls) {
                startTlsRequired = true;
                Smtp.RequiresStartTls = true;
                if (supportsStartTls && !tlsUpgraded) {
                    var upgraded = await TryStartTlsAsync();
                    if (upgraded) {
                        tlsUpgraded = true;
                        ResetSmtpFlags();
                        capabilities = await SendEhloAsync(sessionIo.Writer, sessionIo.Reader, helloName, timeoutCts.Token);
                        supportsStartTls = capabilities.Contains("STARTTLS");
                        (mailResp, rcptResp) = await SendMailRcptAsync(sessionIo.Writer, sessionIo.Reader, fromAddress, emailAddress, timeoutCts.Token);
                        Smtp.MailFromResponse = mailResp;
                        Smtp.MailFromStatusCode = ParseStatusCode(mailResp);
                        Smtp.RcptToResponse = rcptResp;
                        Smtp.RcptToStatusCode = ParseStatusCode(rcptResp);
                    } else {
                        startTlsFailed = true;
                        Smtp.Error ??= "STARTTLS required but negotiation failed.";
                    }
                } else if (!supportsStartTls) {
                    startTlsFailed = true;
                    Smtp.Error ??= "STARTTLS required but server does not advertise STARTTLS.";
                }
            }

            InterpretSmtpResponse(rcptResp, Smtp, logger);

            bool canCheckCatchAll = !startTlsRequired || (tlsUpgraded && !startTlsFailed);
            if (enableCatchAll && canCheckCatchAll && !string.IsNullOrWhiteSpace(domain) && !ContainsCrLf(domain)) {
                var randomLocal = $"dd-{Guid.NewGuid():N}";
                await sessionIo.Writer.WriteLineAsync($"RCPT TO:<{randomLocal}@{domain}>").WaitWithCancellation(timeoutCts.Token);
                var catchResp = await ReadResponseAsync(sessionIo.Reader, timeoutCts.Token);
                Smtp.CatchAllResponse = catchResp;
                if (IsPositiveResponse(catchResp)) {
                    Smtp.IsCatchAll = true;
                }
            }

            await sessionIo.Writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
            await sessionIo.Writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
            try {
                await sessionIo.Reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
            } catch (IOException) {
                // ignore disconnect after QUIT
            }

            async Task<bool> TryStartTlsAsync() {
                await sessionIo.Writer.WriteLineAsync("STARTTLS").WaitWithCancellation(timeoutCts.Token);
                var startResp = await ReadResponseAsync(sessionIo.Reader, timeoutCts.Token);
                if (!IsPositiveResponse(startResp)) {
                    return false;
                }
                var tlsStream = new SslStream(network, false, (_, _, _, errors) => {
                    if (errors == SslPolicyErrors.None) {
                        return true;
                    }
                    if (options.AllowInvalidSmtpCertificates) {
                        logger.WriteVerbose("SMTP TLS certificate validation bypassed: {0}", errors);
                        return true;
                    }
                    return false;
                });
                await tlsStream.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
                sessionIo.UpgradeToTls(tlsStream);
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

    private static readonly char[] CrLfChars = { '\r', '\n' };

    private static bool ContainsOrdinalIgnoreCase(string? source, string value) {
        if (source == null || value == null || source.Length == 0 || value.Length == 0) {
            return false;
        }
        return source.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
    }

    private static bool ContainsCrLf(string? value) {
        if (value == null || value.Length == 0) {
            return false;
        }
        return value.IndexOfAny(CrLfChars) >= 0;
    }

}
