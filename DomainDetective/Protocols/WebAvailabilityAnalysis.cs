using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Probes public web availability and, optionally, direct origin TLS health.
/// </summary>
/// <remarks>
/// The analysis intentionally stays provider-neutral. It records HTTP status,
/// redirects, selected response headers, and optional origin TLS certificate
/// facts so callers can reason about CDN/proxy and origin disagreements without
/// baking a specific hosting provider into DomainDetective.
/// </remarks>
public sealed class WebAvailabilityAnalysis : IHasAssessments {
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }

    /// <summary>Gets the public endpoint probe result.</summary>
    public WebAvailabilityHttpResult? PublicEndpoint { get; private set; }

    /// <summary>Gets direct origin TLS probe results when requested.</summary>
    public List<WebAvailabilityOriginTlsResult> OriginTlsEndpoints { get; } = new();

    /// <summary>Gets selected public response headers useful for proxy/CDN diagnostics.</summary>
    public Dictionary<string, string> PublicResponseSignals { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets a value indicating whether the public endpoint returned an acceptable status.</summary>
    public bool PublicEndpointAvailable => PublicEndpoint?.Available == true;

    /// <summary>Gets a value indicating whether at least one configured origin TLS endpoint succeeded.</summary>
    public bool AnyOriginTlsEndpointAvailable => OriginTlsEndpoints.Count > 0 && OriginTlsEndpoints.Any(static endpoint => endpoint.Success);

    /// <summary>Gets a value indicating whether the public endpoint worked while a configured origin TLS endpoint failed.</summary>
    public bool PublicAvailableButOriginTlsFailed => PublicEndpointAvailable && OriginTlsEndpoints.Any(static endpoint => !endpoint.Success);

    /// <summary>Structured assessments captured during web availability analysis.</summary>
    public List<Assessment> Assessments { get; } = new();

    /// <summary>Actionable recommendations derived from assessments.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>
    /// Analyzes the public URL and optional origin TLS endpoints.
    /// </summary>
    public async Task AnalyzeAsync(
        string url,
        WebAvailabilityOptions? options = null,
        InternalLogger? logger = null,
        CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(url)) {
            throw new ArgumentException("URL must not be empty.", nameof(url));
        }

        options ??= new WebAvailabilityOptions();
        logger ??= new InternalLogger();
        Subject = url;
        PublicResponseSignals.Clear();
        OriginTlsEndpoints.Clear();
        Assessments.Clear();
        PublicEndpoint = null;

        using var collector = AssessmentCollector.ForAnalysis(logger, this, category: "WEBAVAILABILITY", target: url);
        PublicEndpoint = await ProbePublicEndpointAsync(url, options, logger, cancellationToken).ConfigureAwait(false);
        foreach (var endpoint in options.OriginTlsEndpoints) {
            var result = await ProbeOriginTlsAsync(endpoint, options, logger, cancellationToken).ConfigureAwait(false);
            OriginTlsEndpoints.Add(result);
        }

        if (PublicAvailableButOriginTlsFailed) {
            logger.WriteWarningCode(
                WebAvailabilityCodes.PublicAvailableOriginTlsFailed,
                "Public web endpoint is available but one or more configured origin TLS probes failed.");
        }
    }

    private async Task<WebAvailabilityHttpResult> ProbePublicEndpointAsync(
        string url,
        WebAvailabilityOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var stopwatch = Stopwatch.StartNew();
        var result = new WebAvailabilityHttpResult {
            InitialUrl = url
        };

        try {
            using var handler = CreateHttpHandler(options);
            using var client = new HttpClient(handler) { Timeout = options.Timeout };
            var initialUri = new Uri(url, UriKind.Absolute);
            var currentUri = initialUri;
            var currentMethod = options.Method;
            var visited = new HashSet<string>(StringComparer.Ordinal);

            while (true) {
                if (!visited.Add(currentUri.AbsoluteUri)) {
                    result.RedirectLoop = true;
                    result.FailureKind = WebAvailabilityFailureKind.RedirectLoop;
                    result.FailureReason = "Redirect loop detected.";
                    logger.WriteErrorCode(WebAvailabilityCodes.RedirectLoop, "Redirect loop detected for {0}", currentUri.AbsoluteUri);
                    break;
                }

                result.RedirectChain.Add(currentUri.AbsoluteUri);
                using var request = new HttpRequestMessage(currentMethod, currentUri);
                ApplyRequestHeaders(request, options, initialUri, currentUri);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
                result.StatusCode = (int)response.StatusCode;
                result.ReasonPhrase = response.ReasonPhrase;
                result.ProtocolVersion = response.Version?.ToString();
                result.FinalUrl = response.RequestMessage?.RequestUri?.AbsoluteUri ?? currentUri.AbsoluteUri;
                result.ResponseHeaders.Clear();
                PublicResponseSignals.Clear();
                CaptureHeaders(response, result.ResponseHeaders);
                CaptureSignalHeaders(response, PublicResponseSignals);

                if (IsRedirect(response.StatusCode) && response.Headers.Location != null) {
                    if (result.RedirectChain.Count > options.MaxRedirects) {
                        result.TooManyRedirects = true;
                        result.FailureKind = WebAvailabilityFailureKind.TooManyRedirects;
                        result.FailureReason = $"Maximum number of redirects ({options.MaxRedirects}) exceeded.";
                        logger.WriteErrorCode(WebAvailabilityCodes.TooManyRedirects, "Maximum number of redirects ({0}) exceeded.", options.MaxRedirects);
                        break;
                    }

                    currentUri = response.Headers.Location.IsAbsoluteUri
                        ? response.Headers.Location
                        : new Uri(currentUri, response.Headers.Location);
                    currentMethod = GetRedirectMethod(currentMethod, response.StatusCode);
                    result.FinalUrl = currentUri.AbsoluteUri;
                    continue;
                }

                result.Available = result.StatusCode >= 200 && result.StatusCode < 400;
                if (result.Available) {
                    logger.WriteInformationCode(WebAvailabilityCodes.PublicEndpointAvailable, "Public web endpoint returned HTTP {0}.", result.StatusCode);
                } else {
                    result.FailureKind = WebAvailabilityFailureKind.HttpStatus;
                    result.FailureReason = $"HTTP status {result.StatusCode}";
                    logger.WriteWarningCode(WebAvailabilityCodes.PublicEndpointBadStatus, "Public web endpoint returned HTTP {0}.", result.StatusCode);
                }

                break;
            }
        } catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested) {
            result.FailureKind = WebAvailabilityFailureKind.Timeout;
            result.FailureReason = ex.Message;
            logger.WriteErrorCode(WebAvailabilityCodes.PublicEndpointTimeout, "Public web endpoint timed out: {0}", ex.Message);
        } catch (HttpRequestException ex) {
            result.FailureKind = MapHttpFailure(ex);
            result.FailureReason = ex.Message;
            var code = result.FailureKind == WebAvailabilityFailureKind.TlsHandshake
                ? WebAvailabilityCodes.PublicEndpointTlsFailed
                : WebAvailabilityCodes.PublicEndpointRequestFailed;
            logger.WriteErrorCode(code, "Public web endpoint request failed: {0}", ex.Message);
        } catch (AuthenticationException ex) {
            result.FailureKind = WebAvailabilityFailureKind.TlsHandshake;
            result.FailureReason = ex.Message;
            logger.WriteErrorCode(WebAvailabilityCodes.PublicEndpointTlsFailed, "Public web endpoint TLS failed: {0}", ex.Message);
        } catch (Exception ex) when (!cancellationToken.IsCancellationRequested) {
            result.FailureKind = WebAvailabilityFailureKind.Unknown;
            result.FailureReason = ex.Message;
            logger.WriteErrorCode(WebAvailabilityCodes.PublicEndpointRequestFailed, "Public web endpoint check failed: {0}", ex.Message);
        } finally {
            stopwatch.Stop();
            result.Duration = stopwatch.Elapsed;
        }

        return result;
    }

    private static HttpMessageHandler CreateHttpHandler(WebAvailabilityOptions options) {
        var handler = options.HttpHandlerFactory?.Invoke() ?? new HttpClientHandler();
        DisableAutoRedirect(handler);
        return handler;
    }

    private static void DisableAutoRedirect(HttpMessageHandler handler) {
        if (handler == null) {
            throw new ArgumentNullException(nameof(handler));
        }

        var type = handler.GetType();
        var allowAutoRedirect = type.GetProperty("AllowAutoRedirect");
        if (allowAutoRedirect != null && allowAutoRedirect.CanWrite && allowAutoRedirect.PropertyType == typeof(bool)) {
            allowAutoRedirect.SetValue(handler, false, null);
        }

        var maxAutomaticRedirections = type.GetProperty("MaxAutomaticRedirections");
        if (maxAutomaticRedirections != null && maxAutomaticRedirections.CanWrite && maxAutomaticRedirections.PropertyType == typeof(int)) {
            maxAutomaticRedirections.SetValue(handler, 1, null);
        }

        if (handler is DelegatingHandler delegatingHandler && delegatingHandler.InnerHandler != null) {
            DisableAutoRedirect(delegatingHandler.InnerHandler);
        }
    }

    private static void ApplyRequestHeaders(HttpRequestMessage request, WebAvailabilityOptions options, Uri initialUri, Uri currentUri) {
        if (!ShouldSendRequestHeaders(initialUri, currentUri)) {
            return;
        }

        foreach (var header in options.Headers.Where(static header => !string.IsNullOrWhiteSpace(header.Key))) {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value ?? string.Empty);
        }
    }

    private static bool ShouldSendRequestHeaders(Uri initialUri, Uri currentUri) {
        return IsSameOrigin(initialUri, currentUri) || IsSameHostHttpToHttpsUpgrade(initialUri, currentUri);
    }

    private static bool IsSameOrigin(Uri left, Uri right) {
        return HasSameSchemeAndHost(left, right) && left.Port == right.Port;
    }

    private static bool IsSameHostHttpToHttpsUpgrade(Uri initialUri, Uri currentUri) {
        return initialUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            && currentUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            && initialUri.Host.Equals(currentUri.Host, StringComparison.OrdinalIgnoreCase)
            && IsDefaultHttpPort(initialUri)
            && IsDefaultHttpsPort(currentUri);
    }

    private static bool HasSameSchemeAndHost(Uri left, Uri right) {
        return left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase)
            && left.Host.Equals(right.Host, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDefaultHttpPort(Uri uri) {
        return uri.IsDefaultPort || uri.Port == 80;
    }

    private static bool IsDefaultHttpsPort(Uri uri) {
        return uri.IsDefaultPort || uri.Port == 443;
    }

    private static HttpMethod GetRedirectMethod(HttpMethod method, HttpStatusCode statusCode) {
        if (statusCode == HttpStatusCode.SeeOther && method != HttpMethod.Head) {
            return HttpMethod.Get;
        }

        if ((statusCode == HttpStatusCode.MovedPermanently || statusCode == HttpStatusCode.Found) && method == HttpMethod.Post) {
            return HttpMethod.Get;
        }

        return method;
    }

    private async Task<WebAvailabilityOriginTlsResult> ProbeOriginTlsAsync(
        WebOriginTlsEndpoint endpoint,
        WebAvailabilityOptions options,
        InternalLogger logger,
        CancellationToken cancellationToken) {
        var result = new WebAvailabilityOriginTlsResult {
            Address = endpoint.Address,
            HostName = endpoint.HostName,
            Port = endpoint.Port
        };

        try {
            using var tls = options.OriginTlsProbeOverride != null
                ? await options.OriginTlsProbeOverride(endpoint, options.Timeout, cancellationToken).ConfigureAwait(false)
                : await TlsProbe.ProbeWithFailureEvidenceAsync(endpoint.Address, endpoint.HostName, endpoint.Port, options.Timeout, cancellationToken).ConfigureAwait(false);

            result.Protocol = tls.Protocol.ToString();
            result.CipherSuite = tls.CipherSuite;
            result.CertificateSubject = tls.CertificateSubject;
            result.CertificateIssuer = tls.CertificateIssuer;
            result.NotBefore = tls.NotBefore;
            result.NotAfter = tls.NotAfter;
            result.CertificateValid = tls.CertificateValid;
            result.HostnameMatch = tls.HostnameMatch;
            result.ChainValid = tls.ChainValid;
            result.Success = tls.CertificateValid && tls.HostnameMatch && tls.ChainValid;
            if (result.Success) {
                logger.WriteInformationCode(WebAvailabilityCodes.OriginTlsAvailable, "Origin TLS endpoint {0}:{1} is valid for {2}.", endpoint.Address, endpoint.Port, endpoint.HostName);
            } else {
                result.FailureKind = CertificateFailureKind.TlsHandshake;
                result.FailureReason = "Origin TLS certificate validation did not pass.";
                logger.WriteWarningCode(WebAvailabilityCodes.OriginTlsInvalid, "Origin TLS endpoint {0}:{1} did not pass certificate validation.", endpoint.Address, endpoint.Port);
            }
        } catch (Exception ex) when (!cancellationToken.IsCancellationRequested) {
            result.Success = false;
            result.FailureKind = CertificateFailureClassifier.Classify(ex);
            result.FailureReason = ex.Message;
            logger.WriteErrorCode(WebAvailabilityCodes.OriginTlsFailed, "Origin TLS endpoint {0}:{1} failed: {2}", endpoint.Address, endpoint.Port, ex.Message);
        }

        return result;
    }

    private static bool IsRedirect(HttpStatusCode statusCode) {
        var code = (int)statusCode;
        return code >= 300 && code < 400;
    }

    private static void CaptureHeaders(HttpResponseMessage response, Dictionary<string, string> target) {
        foreach (var header in response.Headers) {
            target[header.Key] = string.Join(",", header.Value);
        }

        if (response.Content != null) {
            foreach (var header in response.Content.Headers) {
                target[header.Key] = string.Join(",", header.Value);
            }
        }
    }

    private static void CaptureSignalHeaders(HttpResponseMessage response, Dictionary<string, string> target) {
        foreach (var header in WebAvailabilitySignalHeaders.Names
            .Select(headerName => new { Name = headerName, Values = GetHeaderValuesOrEmpty(response, headerName) })
            .Where(static header => header.Values.Any())) {
            target[header.Name] = string.Join(",", header.Values);
        }
    }

    private static IEnumerable<string> GetHeaderValuesOrEmpty(HttpResponseMessage response, string headerName) {
        if (response.Headers.TryGetValues(headerName, out var responseValues)) {
            return responseValues;
        }

        if (response.Content != null && response.Content.Headers.TryGetValues(headerName, out var contentValues)) {
            return contentValues;
        }

        return Array.Empty<string>();
    }

    private static WebAvailabilityFailureKind MapHttpFailure(Exception exception) {
        var certificateFailure = CertificateFailureClassifier.Classify(exception);
        return certificateFailure switch {
            CertificateFailureKind.NameResolution => WebAvailabilityFailureKind.NameResolution,
            CertificateFailureKind.Timeout => WebAvailabilityFailureKind.Timeout,
            CertificateFailureKind.TlsHandshake => WebAvailabilityFailureKind.TlsHandshake,
            CertificateFailureKind.ConnectionRefused => WebAvailabilityFailureKind.ConnectionRefused,
            CertificateFailureKind.ConnectionReset => WebAvailabilityFailureKind.ConnectionReset,
            CertificateFailureKind.ConnectionAborted => WebAvailabilityFailureKind.ConnectionAborted,
            CertificateFailureKind.NetworkUnreachable => WebAvailabilityFailureKind.NetworkUnreachable,
            CertificateFailureKind.ConnectionError => WebAvailabilityFailureKind.ConnectionError,
            CertificateFailureKind.Cancelled => WebAvailabilityFailureKind.Cancelled,
            _ => WebAvailabilityFailureKind.Unknown
        };
    }
}

/// <summary>
/// Options for <see cref="WebAvailabilityAnalysis"/>.
/// </summary>
public sealed class WebAvailabilityOptions {
    /// <summary>Gets or sets the request timeout.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Gets or sets the maximum number of redirects to follow.</summary>
    public int MaxRedirects { get; set; } = 10;

    /// <summary>Gets or sets the public HTTP method to use.</summary>
    public HttpMethod Method { get; set; } = HttpMethod.Get;

    /// <summary>Gets extra public HTTP request headers to send.</summary>
    public Dictionary<string, string> Headers { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets direct origin TLS endpoints to probe.</summary>
    public List<WebOriginTlsEndpoint> OriginTlsEndpoints { get; } = new();

    /// <summary>Optional HTTP handler factory for tests and controlled transports.</summary>
    public Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }

    /// <summary>Optional direct-origin TLS probe override for tests and controlled transports.</summary>
    public Func<WebOriginTlsEndpoint, TimeSpan?, CancellationToken, Task<TlsProbe.Result>>? OriginTlsProbeOverride { get; set; }
}

/// <summary>
/// Direct origin endpoint to validate with TLS SNI.
/// </summary>
public sealed class WebOriginTlsEndpoint {
    /// <summary>Initializes a new instance of the <see cref="WebOriginTlsEndpoint"/> class.</summary>
    public WebOriginTlsEndpoint(IPAddress address, string hostName, int port = 443) {
        Address = address ?? throw new ArgumentNullException(nameof(address));
        HostName = string.IsNullOrWhiteSpace(hostName) ? throw new ArgumentException("Host name must not be empty.", nameof(hostName)) : hostName;
        Port = port;
    }

    /// <summary>Gets the origin IP address.</summary>
    public IPAddress Address { get; }

    /// <summary>Gets the SNI host name.</summary>
    public string HostName { get; }

    /// <summary>Gets the origin TLS port.</summary>
    public int Port { get; }
}

/// <summary>
/// Public web endpoint availability result.
/// </summary>
public sealed class WebAvailabilityHttpResult {
    /// <summary>Gets or sets the initial URL.</summary>
    public string? InitialUrl { get; set; }

    /// <summary>Gets or sets the final URL after redirects.</summary>
    public string? FinalUrl { get; set; }

    /// <summary>Gets redirect and request URLs visited in order.</summary>
    public List<string> RedirectChain { get; } = new();

    /// <summary>Gets the final HTTP status code.</summary>
    public int? StatusCode { get; set; }

    /// <summary>Gets the final HTTP reason phrase.</summary>
    public string? ReasonPhrase { get; set; }

    /// <summary>Gets the final HTTP protocol version.</summary>
    public string? ProtocolVersion { get; set; }

    /// <summary>Gets a value indicating whether the endpoint is available.</summary>
    public bool Available { get; set; }

    /// <summary>Gets a value indicating whether a redirect loop was detected.</summary>
    public bool RedirectLoop { get; set; }

    /// <summary>Gets a value indicating whether the redirect count exceeded the configured limit.</summary>
    public bool TooManyRedirects { get; set; }

    /// <summary>Gets the probe duration.</summary>
    public TimeSpan Duration { get; set; }

    /// <summary>Gets selected response headers from the final response.</summary>
    public Dictionary<string, string> ResponseHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets the normalized failure kind, if any.</summary>
    public WebAvailabilityFailureKind FailureKind { get; set; }

    /// <summary>Gets the failure reason, if any.</summary>
    public string? FailureReason { get; set; }
}

/// <summary>
/// Direct origin TLS availability result.
/// </summary>
public sealed class WebAvailabilityOriginTlsResult {
    /// <summary>Gets or sets the origin IP address.</summary>
    public IPAddress? Address { get; set; }

    /// <summary>Gets or sets the SNI host name.</summary>
    public string? HostName { get; set; }

    /// <summary>Gets or sets the origin port.</summary>
    public int Port { get; set; }

    /// <summary>Gets or sets a value indicating whether the TLS certificate is valid for this origin probe.</summary>
    public bool Success { get; set; }

    /// <summary>Gets or sets a value indicating whether the certificate validated.</summary>
    public bool CertificateValid { get; set; }

    /// <summary>Gets or sets a value indicating whether the certificate matches the SNI host name.</summary>
    public bool HostnameMatch { get; set; }

    /// <summary>Gets or sets a value indicating whether the chain validated.</summary>
    public bool ChainValid { get; set; }

    /// <summary>Gets or sets the negotiated TLS protocol.</summary>
    public string? Protocol { get; set; }

    /// <summary>Gets or sets the negotiated cipher suite.</summary>
    public string? CipherSuite { get; set; }

    /// <summary>Gets or sets the certificate subject.</summary>
    public string? CertificateSubject { get; set; }

    /// <summary>Gets or sets the certificate issuer.</summary>
    public string? CertificateIssuer { get; set; }

    /// <summary>Gets or sets the certificate not-before date.</summary>
    public DateTime? NotBefore { get; set; }

    /// <summary>Gets or sets the certificate not-after date.</summary>
    public DateTime? NotAfter { get; set; }

    /// <summary>Gets or sets the normalized TLS failure kind, if any.</summary>
    public CertificateFailureKind FailureKind { get; set; }

    /// <summary>Gets or sets the failure reason, if any.</summary>
    public string? FailureReason { get; set; }
}

/// <summary>
/// Normalized public web availability failure kinds.
/// </summary>
public enum WebAvailabilityFailureKind {
    /// <summary>No failure was observed.</summary>
    None = 0,
    /// <summary>DNS name resolution failed.</summary>
    NameResolution,
    /// <summary>The request timed out.</summary>
    Timeout,
    /// <summary>TLS negotiation or certificate validation failed.</summary>
    TlsHandshake,
    /// <summary>The connection was refused.</summary>
    ConnectionRefused,
    /// <summary>The connection was reset.</summary>
    ConnectionReset,
    /// <summary>The connection was aborted.</summary>
    ConnectionAborted,
    /// <summary>The network was unreachable.</summary>
    NetworkUnreachable,
    /// <summary>A generic connection error occurred.</summary>
    ConnectionError,
    /// <summary>The request was cancelled.</summary>
    Cancelled,
    /// <summary>The final HTTP status was outside the accepted availability range.</summary>
    HttpStatus,
    /// <summary>A redirect loop was detected.</summary>
    RedirectLoop,
    /// <summary>The redirect limit was exceeded.</summary>
    TooManyRedirects,
    /// <summary>An unknown failure occurred.</summary>
    Unknown
}

/// <summary>
/// Diagnostic codes emitted by <see cref="WebAvailabilityAnalysis"/>.
/// </summary>
public static class WebAvailabilityCodes {
    /// <summary>Public endpoint is available.</summary>
    public const string PublicEndpointAvailable = "WEBAVAILABILITY.Public.Available";
    /// <summary>Public endpoint returned a bad status.</summary>
    public const string PublicEndpointBadStatus = "WEBAVAILABILITY.Public.BadStatus";
    /// <summary>Public endpoint request failed.</summary>
    public const string PublicEndpointRequestFailed = "WEBAVAILABILITY.Public.RequestFailed";
    /// <summary>Public endpoint timed out.</summary>
    public const string PublicEndpointTimeout = "WEBAVAILABILITY.Public.Timeout";
    /// <summary>Public endpoint TLS failed.</summary>
    public const string PublicEndpointTlsFailed = "WEBAVAILABILITY.Public.TlsFailed";
    /// <summary>Redirect loop was detected.</summary>
    public const string RedirectLoop = "WEBAVAILABILITY.Public.RedirectLoop";
    /// <summary>Redirect limit was exceeded.</summary>
    public const string TooManyRedirects = "WEBAVAILABILITY.Public.TooManyRedirects";
    /// <summary>Origin TLS endpoint is available.</summary>
    public const string OriginTlsAvailable = "WEBAVAILABILITY.OriginTls.Available";
    /// <summary>Origin TLS endpoint returned invalid certificate facts.</summary>
    public const string OriginTlsInvalid = "WEBAVAILABILITY.OriginTls.Invalid";
    /// <summary>Origin TLS endpoint failed.</summary>
    public const string OriginTlsFailed = "WEBAVAILABILITY.OriginTls.Failed";
    /// <summary>Public endpoint is available while origin TLS failed.</summary>
    public const string PublicAvailableOriginTlsFailed = "WEBAVAILABILITY.OriginTls.PublicAvailableOriginFailed";
}

internal static class WebAvailabilitySignalHeaders {
    public static readonly string[] Names = new[] {
        "Server",
        "Via",
        "CF-Ray",
        "CF-Cache-Status",
        "X-Cache",
        "X-Served-By",
        "X-Fastly-Request-ID",
        "X-GitHub-Request-Id",
        "X-Vercel-Id",
        "X-Amz-Cf-Id",
        "X-Azure-Ref"
    };
}
