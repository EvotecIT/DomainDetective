using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.IO.Compression;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs basic HTTP checks against a web endpoint.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public partial class HttpAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Gets the HTTP status code of the response.</summary>
        public int? StatusCode { get; private set; }
        /// <summary>Gets the time taken to receive the response.</summary>
        public TimeSpan ResponseTime { get; private set; }
        /// <summary>Gets a value indicating whether the HSTS header was present.</summary>
        public bool HstsPresent { get; private set; }
        /// <summary>Gets the max-age value from the HSTS header.</summary>
        public int? HstsMaxAge { get; private set; }
        /// <summary>Gets a value indicating whether includeSubDomains is present in the HSTS header.</summary>
        public bool HstsIncludesSubDomains { get; private set; }
        /// <summary>Gets a value indicating whether the HSTS max-age is shorter than 18 weeks.</summary>
        public bool HstsTooShort { get; private set; }
        /// <summary>Collects unknown or invalid HSTS directives.</summary>
        public List<string> UnknownHstsDirectives { get; private set; } = new();
        /// <summary>Gets a value indicating whether the host is on the HSTS preload list.</summary>
        public bool HstsPreloaded { get; private set; }
        /// <summary>Gets a value indicating whether the preload token was found in the HSTS header.</summary>
        public bool HstsPreloadDirectivePresent { get; private set; }
        /// <summary>Gets a value indicating whether the HSTS header meets preload list requirements.</summary>
        public bool HstsPreloadEligible { get; private set; }
        /// <summary>Gets a value indicating whether the X-XSS-Protection header was present.</summary>
        public bool XssProtectionPresent { get; private set; }
        /// <summary>Gets a value indicating whether the Expect-CT header was present.</summary>
        public bool ExpectCtPresent { get; private set; }
        /// <summary>Gets the max-age value from the Expect-CT header.</summary>
        public int? ExpectCtMaxAge { get; private set; }
        /// <summary>Gets the report-uri value from the Expect-CT header.</summary>
        public string? ExpectCtReportUri { get; private set; }
        /// <summary>Gets a value indicating whether the Public-Key-Pins header was present.</summary>
        [Obsolete("Public-Key-Pins header is deprecated.")]
        public bool PublicKeyPinsPresent { get; private set; }
        /// <summary>Gets a value indicating whether the Content-Security-Policy contains unsafe directives.</summary>
        public bool CspUnsafeDirectives { get; private set; }
        /// <summary>Gets a collection of detected security headers.</summary>
        public Dictionary<string, SecurityHeader> SecurityHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets a collection of security headers that were not present.</summary>
        public HashSet<string> MissingSecurityHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets a value indicating whether the endpoint was reachable.</summary>
        public bool IsReachable { get; private set; }
        /// <summary>If <see cref="IsReachable"/> is false, explains why.</summary>
        public string? FailureReason { get; private set; }
        /// <summary>Gets the HTTP protocol version returned by the server.</summary>
        public Version? ProtocolVersion { get; private set; }
        /// <summary>Gets a value indicating whether the server supports HTTP/2.</summary>
        public bool Http2Supported { get; private set; }
        /// <summary>Gets a value indicating whether the server supports HTTP/3.</summary>
        public bool Http3Supported { get; private set; }
        /// <summary>Gets the QUIC version advertised in the Alt-Svc header.</summary>
        public string? QuicVersion { get; private set; }
        /// <summary>Gets the value of the Server header if present.</summary>
        public string? ServerHeader { get; private set; }
        /// <summary>Raw NEL header if present.</summary>
        public string? NelRaw { get; private set; }
        /// <summary>Raw Report-To header if present.</summary>
        public string? ReportToRaw { get; private set; }
        /// <summary>Raw speculation-rules header if present.</summary>
        public string? SpeculationRulesRaw { get; private set; }
        /// <summary>Gets the response body when <c>captureBody</c> is enabled.</summary>
        public string? Body { get; private set; }
        /// <summary>Gets the decompressed body length in bytes when <c>captureBody</c> is enabled.</summary>
        public int? BodyLength { get; private set; }
        /// <summary>Gets the SHA-256 hash of the decompressed body when <c>captureBody</c> is enabled.</summary>
        public string? BodySha256 { get; private set; }
        /// <summary>Gets a value indicating whether HTTPS content references insecure HTTP resources.</summary>
        public bool MixedContentDetected { get; private set; }
        /// <summary>Gets the number of forms with insecure http:// action URLs on an HTTPS page.</summary>
        public int InsecureFormsCount { get; private set; }
        /// <summary>Captures representative insecure form action URLs found on page.</summary>
        public List<string> InsecureFormActions { get; } = new();
        /// <summary>Gets a value indicating whether a Permissions-Policy header was present.</summary>
        public bool PermissionsPolicyPresent { get; private set; }
        /// <summary>Gets parsed directives from the Permissions-Policy header.</summary>
        public Dictionary<string, string> PermissionsPolicy { get; } = new(StringComparer.OrdinalIgnoreCase);
        /// <summary>Gets the value of the Referrer-Policy header if present.</summary>
        public string? ReferrerPolicy { get; private set; }
        /// <summary>Gets the value of the X-Frame-Options header if present.</summary>
        public string? XFrameOptions { get; private set; }
        /// <summary>Gets the value of the Cross-Origin-Opener-Policy header if present.</summary>
        public string? CrossOriginOpenerPolicy { get; private set; }
        /// <summary>Gets the value of the Cross-Origin-Embedder-Policy header if present.</summary>
        public string? CrossOriginEmbedderPolicy { get; private set; }
        /// <summary>Gets the value of the Cross-Origin-Resource-Policy header if present.</summary>
        public string? CrossOriginResourcePolicy { get; private set; }
        /// <summary>Gets the value of the X-Permitted-Cross-Domain-Policies header if present.</summary>
        public string? XPermittedCrossDomainPolicies { get; private set; }
        /// <summary>Gets a value indicating whether the Origin-Agent-Cluster header was present.</summary>
        public bool OriginAgentClusterPresent { get; private set; }
        /// <summary>Gets a value indicating whether Origin-Agent-Cluster is enabled.</summary>
        public bool OriginAgentClusterEnabled { get; private set; }
	        /// <summary>Gets the URLs visited when following redirects.</summary>
	        public List<string> VisitedUrls { get; } = new();
	        /// <summary>Gets or sets the maximum number of redirects to follow.</summary>
	        public int MaxRedirects { get; set; } = 10;
            /// <summary>Optional factory used to create a constrained outbound HTTP handler.</summary>
            public Func<HttpMessageHandler>? HttpHandlerFactory { get; set; }
	        /// <summary>HTTP method used for the request.</summary>
	        public HttpRequestMethod RequestMethodUsed { get; private set; } = HttpRequestMethod.Get;
	        /// <summary>True when TLS validation was disabled for the request.</summary>
	        public bool TlsValidationDisabled { get; private set; }
	        /// <summary>Proxy URL used for the request when configured.</summary>
	        public string? ProxyUsed { get; private set; }
	        /// <summary>Request header names that were sent (best-effort; excludes defaults).</summary>
	        public List<string> RequestHeaderNames { get; } = new();
	        /// <summary>Information disclosure headers observed (best-effort).</summary>
	        public Dictionary<string, string> InformationDisclosureHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
	        /// <summary>Caching headers observed (best-effort).</summary>
	        public Dictionary<string, string> CachingHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
	        /// <summary>Deprecated security headers observed.</summary>
	        public HashSet<string> DeprecatedHeadersPresent { get; } = new(StringComparer.OrdinalIgnoreCase);
	        /// <summary>Deprecated security headers that were missing.</summary>
	        public HashSet<string> MissingDeprecatedHeaders { get; } = new(StringComparer.OrdinalIgnoreCase);
	        /// <summary>True when CSP contains a frame-ancestors directive.</summary>
	        public bool CspFrameAncestorsPresent { get; private set; }

	        /// <summary>Gets or sets the HTTP request timeout.</summary>
	        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(100);

#if NET8_0_OR_GREATER
        /// <summary>Gets or sets the HTTP version used for requests.</summary>
        public Version RequestVersion { get; set; } = HttpVersion.Version30;
#else
        /// <summary>Gets or sets the HTTP version used for requests.</summary>
        public Version RequestVersion { get; set; } = HttpVersion.Version11;
#endif

	        private static readonly List<string> _securityHeaderNames = new() {
	            "Content-Security-Policy",
	            "X-Content-Type-Options",
	            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "Expect-CT",
            "Public-Key-Pins",
            "X-Permitted-Cross-Domain-Policies",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy",
	            "Origin-Agent-Cluster"
	        };

	        private static readonly HashSet<string> _deprecatedSecurityHeaders = new(StringComparer.OrdinalIgnoreCase) {
	            "X-XSS-Protection",
	            "Expect-CT",
	            "Public-Key-Pins",
	            "X-Permitted-Cross-Domain-Policies"
	        };

	        private static readonly string[] _informationHeaderNames = new[] {
	            "X-Powered-By",
	            "Server",
	            "X-AspNet-Version",
	            "X-AspNetMvc-Version"
	        };

	        private static readonly string[] _cachingHeaderNames = new[] {
	            "Cache-Control",
	            "Pragma",
	            "Expires",
	            "Last-Modified",
	            "ETag"
	        };

	        private static HashSet<string> _hstsPreloadExact = new(StringComparer.OrdinalIgnoreCase);
	        private static HashSet<string> _hstsPreloadSubdomains = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Loads a Chromium-derived HSTS preload snapshot, optionally gzip-compressed.</summary>
        /// <param name="filePath">File path containing the preload list.</param>
        public static void LoadHstsPreloadList(string filePath) {
            if (!File.Exists(filePath)) {
                return;
            }
            try {
                using var file = File.OpenRead(filePath);
                using var stream = filePath.EndsWith(".gz", StringComparison.OrdinalIgnoreCase)
                    ? (Stream)new GZipStream(file, CompressionMode.Decompress)
                    : file;
                using var document = JsonDocument.Parse(stream);
                var exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var subdomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var root = document.RootElement;
                if (root.ValueKind == JsonValueKind.Array) {
                    foreach (var item in root.EnumerateArray()) {
                        if (item.ValueKind == JsonValueKind.String && NormalizeHstsHost(item.GetString()) is string host) exact.Add(host);
                    }
                } else if (root.TryGetProperty("entries", out var entries)) {
                    foreach (var item in entries.EnumerateArray()) {
                        if (!item.TryGetProperty("name", out var nameProperty) || NormalizeHstsHost(nameProperty.GetString()) is not string host) continue;
                        exact.Add(host);
                        if (item.TryGetProperty("includeSubDomains", out var includeProperty) && includeProperty.ValueKind == JsonValueKind.True) {
                            subdomains.Add(host);
                        }
                    }
                }
                _hstsPreloadExact = exact;
                _hstsPreloadSubdomains = subdomains;
            } catch {
                // ignore malformed preload files
            }
        }

        internal static bool IsHstsPreloadedHost(string host) {
            var normalized = NormalizeHstsHost(host);
            if (normalized == null) return false;
            if (_hstsPreloadExact.Contains(normalized)) return true;
            var offset = normalized.IndexOf('.');
            while (offset >= 0 && offset + 1 < normalized.Length) {
                var parent = normalized.Substring(offset + 1);
                if (_hstsPreloadSubdomains.Contains(parent)) return true;
                offset = normalized.IndexOf('.', offset + 1);
            }
            return false;
        }

        private static string? NormalizeHstsHost(string? host) {
            if (string.IsNullOrWhiteSpace(host)) return null;
            try {
                return new IdnMapping().GetAscii(host!.Trim().TrimEnd('.')).ToLowerInvariant();
            } catch (ArgumentException) {
                return null;
            }
        }

        /// <summary>
        /// Gets the default security headers checked when <see cref="AnalyzeUrl"/> is
        /// called with header collection enabled. The list includes modern headers such
        /// as <c>Content-Security-Policy</c>, <c>Referrer-Policy</c>, <c>X-Frame-Options</c>,
        /// <c>Permissions-Policy</c> and <c>Origin-Agent-Cluster</c>. Modify this list to
        /// customize which headers are captured.
        /// </summary>
        public static IList<string> DefaultSecurityHeaders => _securityHeaderNames;

        /// <summary>Structured assessments captured during HTTP analysis.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Actionable recommendations derived from assessments.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
	        /// Performs an HTTP request to the specified URL.
	        /// </summary>
	        /// <param name="url">The URL to query.</param>
	        /// <param name="checkHsts">Whether to check for the presence of HSTS.</param>
	        /// <param name="logger">Logger used for error reporting.</param>
	        /// <param name="collectHeaders">Whether to collect common security headers.</param>
	        /// <param name="captureBody">Whether to capture the response body.</param>
	        /// <param name="cancellationToken">Token to cancel the operation.</param>
	        /// <param name="requestOptions">Optional request customization options.</param>
	        public async Task AnalyzeUrl(string url, bool checkHsts, InternalLogger logger, bool collectHeaders = false, bool captureBody = false, CancellationToken cancellationToken = default, HttpRequestOptions? requestOptions = null) {
	            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "HTTP", target: url);
	            requestOptions ??= new HttpRequestOptions();
    #if NET8_0_OR_GREATER
                var manualRedirect = HttpHandlerFactory != null || RequestVersion >= HttpVersion.Version30;
                var configurableHandler = HttpHandlerFactory == null ? new HttpClientHandler { AllowAutoRedirect = !manualRedirect, MaxAutomaticRedirections = MaxRedirects } : null;
	#else
	            var configurableHandler = HttpHandlerFactory == null ? new HttpClientHandler { AllowAutoRedirect = false, MaxAutomaticRedirections = MaxRedirects } : null;
	#endif
                using var handler = HttpHandlerFactory?.Invoke() ?? configurableHandler!;
	            ProxyUsed = null;
	            TlsValidationDisabled = requestOptions.DisableTlsValidation;
	            if (!string.IsNullOrWhiteSpace(requestOptions.ProxyUrl)) {
	                try {
	                    if (configurableHandler == null) throw new InvalidOperationException("Proxy options cannot be combined with a custom HTTP handler.");
	                    configurableHandler.UseProxy = true;
	                    configurableHandler.Proxy = new WebProxy(requestOptions.ProxyUrl);
	                    ProxyUsed = requestOptions.ProxyUrl;
	                } catch {
	                    if (configurableHandler != null) {
	                        configurableHandler.UseProxy = false;
	                        configurableHandler.Proxy = null;
	                    }
	                    ProxyUsed = null;
	                }
	            }
	            if (requestOptions.DisableTlsValidation) {
                    if (configurableHandler == null) throw new InvalidOperationException("TLS validation options cannot be combined with a custom HTTP handler.");
    #if NET8_0_OR_GREATER
	                configurableHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
	#else
	                configurableHandler.ServerCertificateCustomValidationCallback = (req, cert, chain, errors) => true;
	#endif
	            }
	            using var client = new HttpClient(handler) { Timeout = Timeout };
            var sw = Stopwatch.StartNew();
            FailureReason = null;
            ProtocolVersion = null;
	            Body = null; BodyLength = null; BodySha256 = null; NelRaw = null; ReportToRaw = null; SpeculationRulesRaw = null;
	            ServerHeader = null;
	            VisitedUrls.Clear();
	            RequestHeaderNames.Clear();
	            InformationDisclosureHeaders.Clear();
	            CachingHeaders.Clear();
	            DeprecatedHeadersPresent.Clear();
	            MissingDeprecatedHeaders.Clear();
	            MixedContentDetected = false;
	            InsecureFormsCount = 0;
	            InsecureFormActions.Clear();
            XssProtectionPresent = false;
            ExpectCtPresent = false;
            ExpectCtMaxAge = null;
            ExpectCtReportUri = null;
#pragma warning disable CS0618
            PublicKeyPinsPresent = false;
#pragma warning restore CS0618
            CspUnsafeDirectives = false;
            HstsMaxAge = null;
            HstsIncludesSubDomains = false;
            HstsTooShort = false;
            HstsPreloaded = false;
            HstsPreloadDirectivePresent = false;
            HstsPreloadEligible = false;
            UnknownHstsDirectives = new List<string>();
            PermissionsPolicyPresent = false;
            PermissionsPolicy.Clear();
            QuicVersion = null;
            ReferrerPolicy = null;
            XFrameOptions = null;
            CrossOriginOpenerPolicy = null;
            CrossOriginEmbedderPolicy = null;
	            CrossOriginResourcePolicy = null;
	            XPermittedCrossDomainPolicies = null;
	            OriginAgentClusterPresent = false;
	            OriginAgentClusterEnabled = false;
	            CspFrameAncestorsPresent = false;
	            SecurityHeaders.Clear();
	            MissingSecurityHeaders.Clear();
	            try {
	                string effectiveScheme;
    #if NET8_0_OR_GREATER
	                var currentUri = new Uri(url);
	                HttpResponseMessage? response = null;
	                var redirects = 0;
	                var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
	                var httpMethod = requestOptions.ToHttpMethod();
	                if (captureBody && httpMethod == HttpMethod.Head) {
	                    httpMethod = HttpMethod.Get;
	                }
	                RequestMethodUsed = httpMethod == HttpMethod.Head
	                    ? HttpRequestMethod.Head
	                    : (httpMethod == HttpMethod.Get ? HttpRequestMethod.Get : requestOptions.Method);
	                while (true) {
	                    if (!visited.Add(currentUri.AbsoluteUri)) {
	                        throw new InvalidOperationException("Redirect loop detected.");
	                    }
	                    VisitedUrls.Add(currentUri.AbsoluteUri);
	                    using var request = new HttpRequestMessage(httpMethod, currentUri) {
	                        Version = RequestVersion,
	                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
	                    };
	                    ApplyRequestHeaders(request, requestOptions);
	                    response?.Dispose();
	                    response = await client.SendAsync(request, cancellationToken);
                    if (manualRedirect && (int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
                        redirects++;
                        if (redirects > MaxRedirects) {
                            throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
                        }
                        currentUri = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(currentUri, response.Headers.Location);
                        continue;
                    }
                    currentUri = response.RequestMessage?.RequestUri ?? currentUri;
                    break;
                }
	                if (!visited.Contains(currentUri.AbsoluteUri)) {
	                    VisitedUrls.Add(currentUri.AbsoluteUri);
	                }
	                HstsPreloaded = IsHstsPreloadedHost(currentUri.Host);
	                effectiveScheme = currentUri.Scheme;
	#else
	                var currentUri = new Uri(url);
	                HttpResponseMessage? response = null;
	                var redirects = 0;
	                var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
	                var httpMethod = requestOptions.ToHttpMethod();
	                if (captureBody && httpMethod == HttpMethod.Head) {
	                    httpMethod = HttpMethod.Get;
	                }
	                RequestMethodUsed = httpMethod == HttpMethod.Head
	                    ? HttpRequestMethod.Head
	                    : (httpMethod == HttpMethod.Get ? HttpRequestMethod.Get : requestOptions.Method);
	                while (true) {
	                    if (!visited.Add(currentUri.AbsoluteUri)) {
	                        throw new InvalidOperationException("Redirect loop detected.");
	                    }
	                    VisitedUrls.Add(currentUri.AbsoluteUri);
	                    response?.Dispose();
	                    using (var request = new HttpRequestMessage(httpMethod, currentUri)) {
	                        ApplyRequestHeaders(request, requestOptions);
	                        response = await client.SendAsync(request, cancellationToken);
	                    }
	                    if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400 && response.Headers.Location != null) {
	                        redirects++;
	                        if (redirects > MaxRedirects) {
	                            throw new InvalidOperationException($"Maximum number of redirects ({MaxRedirects}) exceeded.");
	                        }
                        currentUri = response.Headers.Location.IsAbsoluteUri ? response.Headers.Location : new Uri(currentUri, response.Headers.Location);
                        continue;
                    }
                    currentUri = response.RequestMessage?.RequestUri ?? currentUri;
                    break;
                }
	                if (!visited.Contains(currentUri.AbsoluteUri)) {
	                    VisitedUrls.Add(currentUri.AbsoluteUri);
	                }
	                HstsPreloaded = IsHstsPreloadedHost(currentUri.Host);
	                effectiveScheme = currentUri.Scheme;
	#endif
	                if (response == null) {
	                    throw new InvalidOperationException("HTTP request did not produce a response.");
	                }
                if (VisitedUrls.Count > 1) {
                    var first = VisitedUrls.First();
                    var last = VisitedUrls.Last();
                    if (first.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && last.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteInformationCode(HttpCodes.SecureRedirect, "Initial HTTP request redirected to HTTPS");
                    }
                }
                sw.Stop();
                StatusCode = (int)response.StatusCode;
                ResponseTime = sw.Elapsed;
                IsReachable = response.IsSuccessStatusCode;
                if (IsReachable) {
                    ProtocolVersion = response.Version;
#if NET8_0_OR_GREATER
                    Http3Supported = response.Version >= HttpVersion.Version30;
                    Http2Supported = response.Version >= HttpVersion.Version20;
                    if (RequestVersion >= HttpVersion.Version30 && response.Version < HttpVersion.Version30) {
                        logger?.WriteWarningCode(HttpCodes.Http3Downgrade, "Requested HTTP/3 but server responded with HTTP/{0}", response.Version);
                    }
#else
                    Http2Supported = response.Version.Major >= 2;
                    Http3Supported = false;
#endif
                }
                string? altSvcHeader = null;
                string? hstsHeader = null;
                string? expectCtHeader = null;
                string? serverHeader = null;
                if (response.Headers.TryGetValues("Alt-Svc", out var altValues)) {
                    altSvcHeader = string.Join(",", altValues);
                }
                if (response.Headers.TryGetValues("Strict-Transport-Security", out var hstsValues)) {
                    hstsHeader = string.Join(",", hstsValues);
                }
                if (response.Headers.TryGetValues("Expect-CT", out var expectCtValues)) {
                    expectCtHeader = string.Join(",", expectCtValues);
                }
                if (response.Headers.TryGetValues("Server", out var serverValues)) {
                    serverHeader = string.Join(",", serverValues);
                }
                if (response.Headers.TryGetValues("NEL", out var nelValues)) {
                    NelRaw = string.Join(",", nelValues);
                }
                if (response.Headers.TryGetValues("Report-To", out var rptValues)) {
                    ReportToRaw = string.Join(",", rptValues);
                }
                if (response.Headers.TryGetValues("speculation-rules", out var specValues) || response.Headers.TryGetValues("Speculation-Rules", out specValues)) {
                    SpeculationRulesRaw = string.Join(",", specValues);
                }
                ServerHeader = serverHeader;
#if NET8_0_OR_GREATER
                if (IsReachable && ProtocolVersion != null && ProtocolVersion >= HttpVersion.Version30) {
                    QuicVersion = ParseQuicVersion(altSvcHeader);
                    if (!string.IsNullOrEmpty(QuicVersion) && !QuicVersion.Equals("h3", StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteWarningCode(HttpCodes.H3AltSvcMismatch, "HTTP/3 negotiated but Alt-Svc advertises {0}", QuicVersion);
                    }
                }
	#endif
                if (checkHsts) {
                    // Header presence is tracked regardless of scheme; callers can still use effectiveScheme
                    // to interpret whether the policy would be enforced by user agents.
                    HstsPresent = hstsHeader != null;
                }
                if (collectHeaders) {
                    foreach (var headerName in _securityHeaderNames) {
                        if (response.Headers.TryGetValues(headerName, out var values) ||
                            response.Content.Headers.TryGetValues(headerName, out values)) {
                            SecurityHeaders[headerName] = new SecurityHeader(headerName, string.Join(",", values));
                            if (_deprecatedSecurityHeaders.Contains(headerName)) {
                                DeprecatedHeadersPresent.Add(headerName);
                            }
                        } else {
                            MissingSecurityHeaders.Add(headerName);
                            if (_deprecatedSecurityHeaders.Contains(headerName)) {
                                MissingDeprecatedHeaders.Add(headerName);
                            }
                        }
                    }
                    if (!HstsPresent && SecurityHeaders.TryGetValue("Strict-Transport-Security", out var hsts)) {
                        HstsPresent = true;
                        hstsHeader = hsts.Value;
                    }
                    XssProtectionPresent = SecurityHeaders.ContainsKey("X-XSS-Protection");
                    if (SecurityHeaders.TryGetValue("X-XSS-Protection", out var xss))
                    {
                        var xv = (xss.Value ?? string.Empty).Trim();
                        if (xv.Equals("0", StringComparison.OrdinalIgnoreCase))
                        {
                            logger?.WriteWarningCode(HttpCodes.XssProtectionDisabled, "X-XSS-Protection is set to 0 (disabled)");
                        }
                    }
                    ExpectCtPresent = SecurityHeaders.ContainsKey("Expect-CT");
#pragma warning disable CS0618
                    PublicKeyPinsPresent = SecurityHeaders.ContainsKey("Public-Key-Pins");
                    if (PublicKeyPinsPresent) {
                        logger?.WriteWarningCode(HttpCodes.HpkpDeprecated, "Public-Key-Pins header is deprecated and should not be used.");
                    }
#pragma warning restore CS0618
	                    if (SecurityHeaders.TryGetValue("Content-Security-Policy", out var csp)) {
	                        ParseContentSecurityPolicy(csp.Value);
	                    }
	                    // CSP frame-ancestors makes X-Frame-Options optional.
	                    if (CspFrameAncestorsPresent) {
	                        MissingSecurityHeaders.Remove("X-Frame-Options");
	                    }
	                    if (response.Headers.TryGetValues("Content-Security-Policy-Report-Only", out var cspRoVals) || response.Content.Headers.TryGetValues("Content-Security-Policy-Report-Only", out cspRoVals)) {
	                        SecurityHeaders["Content-Security-Policy-Report-Only"] = new SecurityHeader("Content-Security-Policy-Report-Only", string.Join(",", cspRoVals));
	                        logger?.WriteWarningCode(HttpCodes.CspReportOnly, "CSP is report-only; consider enforcing after fixing violations");
	                    }
                    if (SecurityHeaders.TryGetValue("X-Content-Type-Options", out var xcto)) {
                        var xv = (xcto.Value ?? string.Empty).Trim();
                        if (!string.IsNullOrEmpty(xv) && !xv.Equals("nosniff", StringComparison.OrdinalIgnoreCase)) {
                            logger?.WriteWarningCode(HttpCodes.XContentTypeOptionsInvalid, "X-Content-Type-Options should be 'nosniff' (found: {0})", xv);
                        }
                    }
                    if (SecurityHeaders.TryGetValue("Permissions-Policy", out var pp)) {
                        ParsePermissionsPolicy(pp.Value);
                        // Warn if any feature policy is wildcard or empty
                        if (PermissionsPolicyPresent && PermissionsPolicy.Any(kv => string.IsNullOrWhiteSpace(kv.Value) || kv.Value == "*")) {
                            logger?.WriteWarningCode(HttpCodes.PermissionsPolicyWeak, "Permissions-Policy contains empty or wildcard values");
                        }
                    }
                    if (SecurityHeaders.TryGetValue("Referrer-Policy", out var rp)) {
                        ReferrerPolicy = rp.Value;
                        var rv = (ReferrerPolicy ?? string.Empty).Trim();
                        if (rv.IndexOf("unsafe-url", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            logger?.WriteWarningCode(HttpCodes.ReferrerPolicyUnsafeUrl, "Referrer-Policy contains unsafe-url");
                        }
                    }
                    if (SecurityHeaders.TryGetValue("X-Frame-Options", out var xfo)) {
                        XFrameOptions = xfo.Value;
                        var xv = (XFrameOptions ?? string.Empty).Trim();
                        var valid = xv.Equals("DENY", StringComparison.OrdinalIgnoreCase) || xv.Equals("SAMEORIGIN", StringComparison.OrdinalIgnoreCase);
                        if (!string.IsNullOrEmpty(xv) && !valid) {
                            logger?.WriteWarningCode(HttpCodes.XFrameOptionsInvalid, "X-Frame-Options should be DENY or SAMEORIGIN (found: {0})", xv);
                        }
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Opener-Policy", out var coop)) {
                        CrossOriginOpenerPolicy = coop.Value;
                        var v = (CrossOriginOpenerPolicy ?? string.Empty).Trim();
                        if (string.IsNullOrEmpty(v) || v.Equals("unsafe-none", StringComparison.OrdinalIgnoreCase)) {
                            logger?.WriteWarningCode(HttpCodes.COOPWeak, "COOP is missing or set to unsafe-none");
                        }
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Embedder-Policy", out var coep)) {
                        CrossOriginEmbedderPolicy = coep.Value;
                        var v = (CrossOriginEmbedderPolicy ?? string.Empty).Trim();
                        if (!v.Equals("require-corp", StringComparison.OrdinalIgnoreCase)) {
                            logger?.WriteWarningCode(HttpCodes.COEPWeak, "COEP should be 'require-corp' for strong isolation");
                        }
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Resource-Policy", out var corp)) {
                        CrossOriginResourcePolicy = corp.Value;
                        var v = (CrossOriginResourcePolicy ?? string.Empty).Trim();
                        if (!(v.Equals("same-origin", StringComparison.OrdinalIgnoreCase) || v.Equals("same-site", StringComparison.OrdinalIgnoreCase))) {
                            logger?.WriteWarningCode(HttpCodes.CORPWeak, "CORP should be 'same-origin' or 'same-site'");
                        }
                    }
                    if (SecurityHeaders.TryGetValue("X-Permitted-Cross-Domain-Policies", out var xpcdp)) {
                        XPermittedCrossDomainPolicies = xpcdp.Value;
                    }
                    if (SecurityHeaders.TryGetValue("Origin-Agent-Cluster", out var oac)) {
                        ParseOriginAgentCluster(oac.Value);
                    }
	                    if (SecurityHeaders.TryGetValue("Expect-CT", out var ect)) {
	                        ParseExpectCt(ect.Value);
	                    }

	                    CaptureNamedHeaders(response, _informationHeaderNames, InformationDisclosureHeaders);
	                    CaptureNamedHeaders(response, _cachingHeaderNames, CachingHeaders);
	                }
                if (hstsHeader != null) {
                    ParseHsts(hstsHeader);
                    if (HstsMaxAge.HasValue && HstsMaxAge.Value <= 0)
                    {
                        logger?.WriteWarningCode(HttpCodes.HstsMaxAgeZero, "HSTS max-age is 0 (policy disabled)");
                    }
                }
                if (expectCtHeader != null && !collectHeaders) {
                    ParseExpectCt(expectCtHeader);
                }
	                // Emit fine-grained assessments
	                if (checkHsts && effectiveScheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !HstsPresent) {
	                    logger?.WriteWarningCode(HttpCodes.HstsMissing, "Strict-Transport-Security header missing");
	                }
                if (HstsTooShort) {
                    logger?.WriteWarningCode(HttpCodes.HstsTooShort, "HSTS max-age is shorter than 18 weeks");
                }
                if (UnknownHstsDirectives != null) {
                    foreach (var unk in UnknownHstsDirectives) {
                        logger?.WriteWarningCode(HttpCodes.HstsUnknownDirective, "Unknown HSTS directive: {0}", unk);
                    }
                }
                if (CspUnsafeDirectives) {
                    logger?.WriteWarningCode(HttpCodes.CspUnsafe, "Content-Security-Policy contains unsafe directives");
                }
                if (MixedContentDetected) {
                    logger?.WriteWarningCode(HttpCodes.MixedContent, "HTTPS page references insecure http:// resources");
                }
                if (XssProtectionPresent) {
                    logger?.WriteWarningCode(HttpCodes.XssProtectionDeprecated, "X-XSS-Protection header is obsolete in modern browsers");
                }
                if (ExpectCtPresent || expectCtHeader != null) {
                    logger?.WriteWarningCode(HttpCodes.ExpectCtDeprecated, "Expect-CT header is obsolete");
                }
                if (collectHeaders && MissingSecurityHeaders.Count > 0) {
                    foreach (var miss in MissingSecurityHeaders) {
                        var code = miss switch {
                            "Content-Security-Policy" => HttpCodes.MissingHeaderCsp,
                            "Referrer-Policy" => HttpCodes.MissingHeaderReferrerPolicy,
                            "X-Frame-Options" => HttpCodes.MissingHeaderXFrameOptions,
                            "Permissions-Policy" => HttpCodes.MissingHeaderPermissionsPolicy,
                            "X-Content-Type-Options" => HttpCodes.MissingHeaderXContentTypeOptions,
                            "Cross-Origin-Opener-Policy" => HttpCodes.MissingHeaderCOOP,
                            "Cross-Origin-Embedder-Policy" => HttpCodes.MissingHeaderCOEP,
                            "Cross-Origin-Resource-Policy" => HttpCodes.MissingHeaderCORP,
                            "Origin-Agent-Cluster" => HttpCodes.MissingHeaderOAC,
                            "X-Permitted-Cross-Domain-Policies" => HttpCodes.MissingHeaderXPermittedCrossDomainPolicies,
                            _ => null
                        };
                        if (code != null) {
                            logger?.WriteWarningCode(code, "Missing recommended security header: {0}", miss);
                        }
                    }
                }
                // Positive/presence signals to enrich dataset (emitted after warning checks)
                try {
                    if (HstsPresent && !HstsTooShort) {
                        logger?.WriteInformationCode(HttpCodes.HstsPresent, "HSTS present");
                    }
                    bool HasHeader(string name) => SecurityHeaders.ContainsKey(name);
                    if (HasHeader("Content-Security-Policy") && !CspUnsafeDirectives && !SecurityHeaders.ContainsKey("Content-Security-Policy-Report-Only")) {
                        logger?.WriteInformationCode(HttpCodes.CspPresent, "CSP present");
                    }
                    if (!string.IsNullOrWhiteSpace(ReferrerPolicy)) {
                        logger?.WriteInformationCode(HttpCodes.ReferrerPolicyPresent, "Referrer-Policy present");
                    }
                    if (!string.IsNullOrWhiteSpace(XFrameOptions)) {
                        var xv2 = (XFrameOptions ?? string.Empty).Trim();
                        var valid2 = xv2.Equals("DENY", StringComparison.OrdinalIgnoreCase) || xv2.Equals("SAMEORIGIN", StringComparison.OrdinalIgnoreCase);
                        if (valid2) logger?.WriteInformationCode(HttpCodes.XFrameOptionsPresent, "X-Frame-Options present");
                    }
                    if (HasHeader("X-Content-Type-Options")) {
                        var xv3 = (SecurityHeaders["X-Content-Type-Options"].Value ?? string.Empty).Trim();
                        if (xv3.Equals("nosniff", StringComparison.OrdinalIgnoreCase)) {
                            logger?.WriteInformationCode(HttpCodes.XContentTypeOptionsPresent, "X-Content-Type-Options nosniff set");
                        }
                    }
                    if (PermissionsPolicyPresent && !(PermissionsPolicy?.Any(kv => string.IsNullOrWhiteSpace(kv.Value) || kv.Value == "*") ?? false)) {
                        logger?.WriteInformationCode(HttpCodes.PermissionsPolicyPresent, "Permissions-Policy present");
                    }
                    if (!string.IsNullOrWhiteSpace(CrossOriginOpenerPolicy) && !(CrossOriginOpenerPolicy ?? "").Trim().Equals("unsafe-none", StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteInformationCode(HttpCodes.COOPPresent, "COOP present");
                    }
                    if (!string.IsNullOrWhiteSpace(CrossOriginEmbedderPolicy) && (CrossOriginEmbedderPolicy ?? string.Empty).Trim().Equals("require-corp", StringComparison.OrdinalIgnoreCase)) {
                        logger?.WriteInformationCode(HttpCodes.COEPPresent, "COEP present");
                    }
                    if (!string.IsNullOrWhiteSpace(CrossOriginResourcePolicy)) {
                        var v3 = (CrossOriginResourcePolicy ?? string.Empty).Trim();
                        if (v3.Equals("same-origin", StringComparison.OrdinalIgnoreCase) || v3.Equals("same-site", StringComparison.OrdinalIgnoreCase)) {
                            logger?.WriteInformationCode(HttpCodes.CORPPresent, "CORP present");
                        }
                    }
                    if (OriginAgentClusterEnabled) {
                        logger?.WriteInformationCode(HttpCodes.OACEnabled, "Origin-Agent-Cluster enabled");
                    }
                } catch { }
                if (captureBody) {
                    try {
                        var bytes = await response.Content.ReadAsByteArrayAsync();
                        BodyLength = bytes?.Length;
                        if (bytes != null) {
#if NET8_0_OR_GREATER
                            var hash = SHA256.HashData(bytes);
#else
                            byte[] hash;
                            using (var sha = SHA256.Create()) { hash = sha.ComputeHash(bytes); }
#endif
                            BodySha256 = BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
                        }
                        string? charset = response.Content?.Headers?.ContentType?.CharSet;
                        Encoding enc;
                        try { enc = !string.IsNullOrWhiteSpace(charset) ? Encoding.GetEncoding(charset!) : Encoding.UTF8; } catch { enc = Encoding.UTF8; }
                        if (bytes != null) {
                            Body = enc.GetString(bytes);
                        } else if (response.Content != null) {
                            Body = await response.Content.ReadAsStringAsync();
                        } else {
                            Body = string.Empty;
                        }
                    } catch {
                        Body = response.Content != null ? await response.Content.ReadAsStringAsync() : string.Empty;
                    }
                    var scheme = response.RequestMessage?.RequestUri?.Scheme;
                    var bodyText = Body ?? string.Empty;
                    if (string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
                        bodyText.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0) {
                        MixedContentDetected = true;
                    }
                    // Detect insecure form actions when page is HTTPS
                    if (string.Equals(scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && bodyText.Length > 0) {
                        try {
                            var html = bodyText;
                            // Simple, fast regex for <form ... action="http://...">
                            var rx = new System.Text.RegularExpressions.Regex(
                                "<form[^>]*action\\s*=\\s*\"(?<url>[^\"]+)\"|<form[^>]*action\\s*=\\s*'(?<url>[^']+)'",
                                System.Text.RegularExpressions.RegexOptions.IgnoreCase,
                                TimeSpan.FromMilliseconds(200));
                            var matches = rx.Matches(html);
                            foreach (System.Text.RegularExpressions.Match m in matches) {
                                var u = m.Groups["url"]?.Value?.Trim();
                                if (string.IsNullOrEmpty(u)) continue;
                                var actionUrl = u!;
                                if (actionUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) {
                                    InsecureFormsCount++;
                                    if (InsecureFormActions.Count < 5 && !InsecureFormActions.Contains(actionUrl)) {
                                        InsecureFormActions.Add(actionUrl);
                                    }
                                }
                            }
                            if (InsecureFormsCount > 0) {
                                logger?.WriteWarningCode(HttpCodes.InsecureFormAction, "Detected {0} form(s) posting to http:// endpoints", InsecureFormsCount);
                            }
                        } catch { /* do not fail analysis on HTML parse issues */ }
                    }
                }
                response.Dispose();
            } catch (HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException se &&
                (se.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound ||
                 se.SocketErrorCode == System.Net.Sockets.SocketError.NoData)) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"DNS lookup failed: {se.Message}";
                logger?.WriteErrorCode(HttpCodes.DnsLookupFailed, "DNS lookup failed for {0}: {1}", url, se.Message);
            } catch (HttpRequestException ex) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteErrorCode(HttpCodes.RequestFailed, "HTTP request failed for {0}: {1}", url, ex.Message);
            } catch (TaskCanceledException ex) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"Timeout: {ex.Message}";
                logger?.WriteErrorCode(HttpCodes.Timeout, "HTTP request timed out for {0}: {1}", url, ex.Message);
	            } catch (Exception ex) when (ex is not InvalidOperationException) {
	                sw.Stop();
	                IsReachable = false;
	                FailureReason = $"HTTP check failed: {ex.Message}";
	                logger?.WriteErrorCode(HttpCodes.CheckFailed, "HTTP check failed for {0}: {1}", url, ex.Message);
	            }
	        }

        /// <summary>
        /// Convenience method to check a URL with default logging.
        /// </summary>
        /// <param name="url">The URL to check.</param>
        /// <param name="checkHsts">Whether to check for HSTS.</param>
        /// <param name="collectHeaders">Whether to collect common security headers.</param>
        /// <param name="captureBody">Whether to capture the response body.</param>
        /// <param name="cancellationToken">Cancellation token to stop the operation.</param>
        /// <returns>A populated <see cref="HttpAnalysis"/> instance.</returns>
        public static async Task<HttpAnalysis> CheckUrl(string url, bool checkHsts = false, bool collectHeaders = false, bool captureBody = false, CancellationToken cancellationToken = default) {
            var analysis = new HttpAnalysis();
            await analysis.AnalyzeUrl(url, checkHsts, new InternalLogger(), collectHeaders, captureBody, cancellationToken);
            return analysis;
        }
    }
}
