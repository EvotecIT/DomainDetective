using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Performs basic HTTP checks against a web endpoint.
    /// </summary>
    public class HttpAnalysis {
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
        public string FailureReason { get; private set; }
        /// <summary>Gets the HTTP protocol version returned by the server.</summary>
        public Version ProtocolVersion { get; private set; }
        /// <summary>Gets a value indicating whether the server supports HTTP/2.</summary>
        public bool Http2Supported { get; private set; }
        /// <summary>Gets a value indicating whether the server supports HTTP/3.</summary>
        public bool Http3Supported { get; private set; }
        /// <summary>Gets the response body when <c>captureBody</c> is enabled.</summary>
        public string Body { get; private set; }
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
        /// <summary>Gets a value indicating whether the Origin-Agent-Cluster header was present.</summary>
        public bool OriginAgentClusterPresent { get; private set; }
        /// <summary>Gets a value indicating whether Origin-Agent-Cluster is enabled.</summary>
        public bool OriginAgentClusterEnabled { get; private set; }
        /// <summary>Gets or sets the maximum number of redirects to follow.</summary>
        public int MaxRedirects { get; set; } = 10;

        /// <summary>Gets or sets the HTTP request timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(100);

#if NET6_0_OR_GREATER
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

        /// <summary>
        /// Gets the default security headers checked when <see cref="AnalyzeUrl"/> is
        /// called with header collection enabled. The list includes modern headers such
        /// as <c>Content-Security-Policy</c>, <c>Referrer-Policy</c>, <c>X-Frame-Options</c>,
        /// <c>Permissions-Policy</c> and <c>Origin-Agent-Cluster</c>. Modify this list to
        /// customize which headers are captured.
        /// </summary>
        public static IList<string> DefaultSecurityHeaders => _securityHeaderNames;

        /// <summary>
        /// Performs an HTTP GET request to the specified URL.
        /// </summary>
        /// <param name="url">The URL to query.</param>
        /// <param name="checkHsts">Whether to check for the presence of HSTS.</param>
        /// <param name="logger">Logger used for error reporting.</param>
        /// <param name="collectHeaders">Whether to collect common security headers.</param>
        /// <param name="captureBody">Whether to capture the response body.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task AnalyzeUrl(string url, bool checkHsts, InternalLogger logger, bool collectHeaders = false, bool captureBody = false, CancellationToken cancellationToken = default) {
#if NET6_0_OR_GREATER
            var manualRedirect = RequestVersion >= HttpVersion.Version30;
            using var handler = new HttpClientHandler { AllowAutoRedirect = !manualRedirect, MaxAutomaticRedirections = MaxRedirects };
#else
            using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = MaxRedirects };
#endif
            using var client = new HttpClient(handler) { Timeout = Timeout };
            var sw = Stopwatch.StartNew();
            FailureReason = null;
            Body = null;
            XssProtectionPresent = false;
            ExpectCtPresent = false;
            ExpectCtMaxAge = null;
            ExpectCtReportUri = null;
            PublicKeyPinsPresent = false;
            CspUnsafeDirectives = false;
            HstsMaxAge = null;
            HstsIncludesSubDomains = false;
            HstsTooShort = false;
            PermissionsPolicyPresent = false;
            PermissionsPolicy.Clear();
            ReferrerPolicy = null;
            XFrameOptions = null;
            CrossOriginOpenerPolicy = null;
            CrossOriginEmbedderPolicy = null;
            CrossOriginResourcePolicy = null;
            OriginAgentClusterPresent = false;
            OriginAgentClusterEnabled = false;
            SecurityHeaders.Clear();
            MissingSecurityHeaders.Clear();
            try {
#if NET6_0_OR_GREATER
                var currentUri = new Uri(url);
                HttpResponseMessage response = null;
                var redirects = 0;
                while (true) {
                    var request = new HttpRequestMessage(HttpMethod.Get, currentUri) {
                        Version = RequestVersion,
                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                    };
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
                    break;
                }
#else
                HttpResponseMessage response = await client.GetAsync(url, cancellationToken);
#endif
                sw.Stop();
                StatusCode = (int)response.StatusCode;
                ResponseTime = sw.Elapsed;
                IsReachable = response.IsSuccessStatusCode;
                if (IsReachable) {
                    ProtocolVersion = response.Version;
#if NET6_0_OR_GREATER
                    Http3Supported = response.Version >= HttpVersion.Version30;
                    Http2Supported = response.Version >= HttpVersion.Version20;
#else
                    Http2Supported = response.Version.Major >= 2;
                    Http3Supported = false;
#endif
                }
                string? hstsHeader = null;
                string? expectCtHeader = null;
                if (response.Headers.TryGetValues("Strict-Transport-Security", out var hstsValues)) {
                    hstsHeader = string.Join(",", hstsValues);
                }
                if (response.Headers.TryGetValues("Expect-CT", out var expectCtValues)) {
                    expectCtHeader = string.Join(",", expectCtValues);
                }
                if (checkHsts) {
                    HstsPresent = hstsHeader != null;
                }
                if (collectHeaders) {
                    foreach (var headerName in _securityHeaderNames) {
                        if (response.Headers.TryGetValues(headerName, out var values) ||
                            response.Content.Headers.TryGetValues(headerName, out values)) {
                            SecurityHeaders[headerName] = new SecurityHeader(headerName, string.Join(",", values));
                        } else {
                            MissingSecurityHeaders.Add(headerName);
                        }
                    }
                    if (!HstsPresent && SecurityHeaders.TryGetValue("Strict-Transport-Security", out var hsts)) {
                        HstsPresent = true;
                        hstsHeader = hsts.Value;
                    }
                    XssProtectionPresent = SecurityHeaders.ContainsKey("X-XSS-Protection");
                    ExpectCtPresent = SecurityHeaders.ContainsKey("Expect-CT");
                    PublicKeyPinsPresent = SecurityHeaders.ContainsKey("Public-Key-Pins");
                    if (PublicKeyPinsPresent) {
                        logger?.WriteWarning("Public-Key-Pins header is deprecated and should not be used.");
                    }
                    if (SecurityHeaders.TryGetValue("Content-Security-Policy", out var csp)) {
                        ParseContentSecurityPolicy(csp.Value);
                    }
                    if (SecurityHeaders.TryGetValue("Permissions-Policy", out var pp)) {
                        ParsePermissionsPolicy(pp.Value);
                    }
                    if (SecurityHeaders.TryGetValue("Referrer-Policy", out var rp)) {
                        ReferrerPolicy = rp.Value;
                    }
                    if (SecurityHeaders.TryGetValue("X-Frame-Options", out var xfo)) {
                        XFrameOptions = xfo.Value;
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Opener-Policy", out var coop)) {
                        CrossOriginOpenerPolicy = coop.Value;
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Embedder-Policy", out var coep)) {
                        CrossOriginEmbedderPolicy = coep.Value;
                    }
                    if (SecurityHeaders.TryGetValue("Cross-Origin-Resource-Policy", out var corp)) {
                        CrossOriginResourcePolicy = corp.Value;
                    }
                    if (SecurityHeaders.TryGetValue("Origin-Agent-Cluster", out var oac)) {
                        ParseOriginAgentCluster(oac.Value);
                    }
                    if (SecurityHeaders.TryGetValue("Expect-CT", out var ect)) {
                        ParseExpectCt(ect.Value);
                    }
                }
                if (hstsHeader != null) {
                    ParseHsts(hstsHeader);
                }
                if (expectCtHeader != null && !collectHeaders) {
                    ParseExpectCt(expectCtHeader);
                }
                if (captureBody) {
                    Body = await response.Content.ReadAsStringAsync();
                }
                response.Dispose();
            } catch (HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException se &&
                (se.SocketErrorCode == System.Net.Sockets.SocketError.HostNotFound ||
                 se.SocketErrorCode == System.Net.Sockets.SocketError.NoData)) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"DNS lookup failed: {se.Message}";
                logger?.WriteError("DNS lookup failed for {0}: {1}", url, se.Message);
            } catch (HttpRequestException ex) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"HTTP request failed: {ex.Message}";
                logger?.WriteError("HTTP request failed for {0}: {1}", url, ex.Message);
            } catch (TaskCanceledException ex) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"Timeout: {ex.Message}";
                logger?.WriteError("HTTP request timed out for {0}: {1}", url, ex.Message);
            } catch (Exception ex) when (ex is not InvalidOperationException) {
                sw.Stop();
                IsReachable = false;
                FailureReason = $"HTTP check failed: {ex.Message}";
                logger?.WriteError("HTTP check failed for {0}: {1}", url, ex.Message);
            }
        }

        private void ParseHsts(string headerValue) {
            HstsMaxAge = null;
            HstsIncludesSubDomains = false;
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            var parts = headerValue.Split(';');
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase)) {
                    var value = trimmed.Substring(8);
                    if (int.TryParse(value, out var ma)) {
                        HstsMaxAge = ma;
                    }
                } else if (trimmed.Equals("includesubdomains", StringComparison.OrdinalIgnoreCase)) {
                    HstsIncludesSubDomains = true;
                }
            }
            HstsTooShort = HstsMaxAge.HasValue && HstsMaxAge.Value < 10886400;
        }

        private void ParseContentSecurityPolicy(string headerValue) {
            CspUnsafeDirectives = false;
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            var parts = headerValue.Split(';');
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.IndexOf("'unsafe-inline'", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    trimmed.IndexOf("'unsafe-eval'", StringComparison.OrdinalIgnoreCase) >= 0) {
                    CspUnsafeDirectives = true;
                    break;
                }
            }
        }

        private void ParseExpectCt(string headerValue) {
            ExpectCtMaxAge = null;
            ExpectCtReportUri = null;
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            var parts = headerValue.Split(',');
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase)) {
                    var value = trimmed.Substring(8);
                    if (int.TryParse(value, out var ma)) {
                        ExpectCtMaxAge = ma;
                    }
                } else if (trimmed.StartsWith("report-uri=", StringComparison.OrdinalIgnoreCase)) {
                    var value = trimmed.Substring(11).Trim('"');
                    if (!string.IsNullOrEmpty(value)) {
                        ExpectCtReportUri = value;
                    }
                }
            }
        }

        private void ParsePermissionsPolicy(string headerValue) {
            PermissionsPolicyPresent = false;
            PermissionsPolicy.Clear();
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            PermissionsPolicyPresent = true;
            var parts = headerValue.Split(',');
            foreach (var part in parts) {
                var trimmed = part.Trim();
                var eqIndex = trimmed.IndexOf('=');
                if (eqIndex <= 0) {
                    continue;
                }
                var feature = trimmed.Substring(0, eqIndex).Trim();
                var value = trimmed.Substring(eqIndex + 1).Trim();
                if (value.StartsWith("(") && value.EndsWith(")")) {
                    value = value.Substring(1, value.Length - 2);
                }
                value = value.Replace("\"", string.Empty).Trim();
                PermissionsPolicy[feature] = value;
            }
        }

        private void ParseOriginAgentCluster(string headerValue) {
            OriginAgentClusterPresent = false;
            OriginAgentClusterEnabled = false;
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            OriginAgentClusterPresent = true;
            OriginAgentClusterEnabled = headerValue.Trim().Equals("?1", StringComparison.Ordinal);
        }

        /// <summary>
        /// Convenience method to check a URL with default logging.
        /// </summary>
        /// <param name="url">The URL to check.</param>
        /// <param name="checkHsts">Whether to check for HSTS.</param>
        /// <param name="collectHeaders">Whether to collect common security headers.</param>
        /// <param name="captureBody">Whether to capture the response body.</param>
        /// <returns>A populated <see cref="HttpAnalysis"/> instance.</returns>
        public static async Task<HttpAnalysis> CheckUrl(string url, bool checkHsts = false, bool collectHeaders = false, bool captureBody = false, CancellationToken cancellationToken = default) {
            var analysis = new HttpAnalysis();
            await analysis.AnalyzeUrl(url, checkHsts, new InternalLogger(), collectHeaders, captureBody, cancellationToken);
            return analysis;
        }
    }
}