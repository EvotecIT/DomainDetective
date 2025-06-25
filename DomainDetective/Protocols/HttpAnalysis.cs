using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
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
        /// <summary>Gets a value indicating whether the Public-Key-Pins header was present.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public bool PublicKeyPinsPresent { get; private set; }
        /// <summary>Gets the max-age value from the Public-Key-Pins header.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public int PublicKeyPinsMaxAge { get; private set; }
        /// <summary>Gets a value indicating whether includeSubDomains is present in the Public-Key-Pins header.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public bool PublicKeyPinsIncludesSubDomains { get; private set; }
        /// <summary>Gets a value indicating whether all retrieved pins were syntactically valid.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public bool PublicKeyPinsValid { get; private set; }
        /// <summary>Gets the list of SHA-256 pins.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public List<string> PublicKeyPins { get; } = new();
        /// <summary>Gets the raw Public-Key-Pins header.</summary>
        [Obsolete("Public-Key-Pins has been deprecated and should not be used.")]
        public string? PublicKeyPinsHeader { get; private set; }
        /// <summary>Gets a collection of detected security headers.</summary>
        public Dictionary<string, string> SecurityHeaders { get; } = new();
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
        /// <summary>Gets or sets the maximum number of redirects to follow.</summary>
        public int MaxRedirects { get; set; } = 10;

        /// <summary>Gets or sets the HTTP request timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(100);

        private static readonly string[] _securityHeaderNames = new[] {
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
            "Cross-Origin-Resource-Policy"
        };

        /// <summary>
        /// Performs an HTTP GET request to the specified URL.
        /// </summary>
        /// <param name="url">The URL to query.</param>
        /// <param name="checkHsts">Whether to check for the presence of HSTS.</param>
        /// <param name="logger">Logger used for error reporting.</param>
        /// <param name="collectHeaders">Whether to collect common security headers.</param>
        /// <param name="captureBody">Whether to capture the response body.</param>
        public async Task AnalyzeUrl(string url, bool checkHsts, InternalLogger logger, bool collectHeaders = false, bool captureBody = false) {
#if NET6_0_OR_GREATER
            var requestVersion = HttpVersion.Version30;
            var manualRedirect = requestVersion >= HttpVersion.Version30;
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
            PublicKeyPinsPresent = false;
            PublicKeyPinsHeader = null;
            PublicKeyPinsValid = false;
            PublicKeyPins.Clear();
            PublicKeyPinsMaxAge = 0;
            PublicKeyPinsIncludesSubDomains = false;
            HstsMaxAge = null;
            HstsIncludesSubDomains = false;
            HstsTooShort = false;
            SecurityHeaders.Clear();
            MissingSecurityHeaders.Clear();
            try {
#if NET6_0_OR_GREATER
                var currentUri = new Uri(url);
                HttpResponseMessage response = null;
                var redirects = 0;
                while (true) {
                    var request = new HttpRequestMessage(HttpMethod.Get, currentUri) {
                        Version = requestVersion,
                        VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                    };
                    response?.Dispose();
                    response = await client.SendAsync(request);
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
                HttpResponseMessage response = await client.GetAsync(url);
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
                if (response.Headers.TryGetValues("Strict-Transport-Security", out var hstsValues)) {
                    hstsHeader = string.Join(",", hstsValues);
                }
                string? hpkpHeader = null;
                if (response.Headers.TryGetValues("Public-Key-Pins", out var hpkpValues)) {
                    hpkpHeader = string.Join(";", hpkpValues);
                }
                if (checkHsts) {
                    HstsPresent = hstsHeader != null;
                }
                if (collectHeaders) {
                    foreach (var headerName in _securityHeaderNames) {
                        if (response.Headers.TryGetValues(headerName, out var values) ||
                            response.Content.Headers.TryGetValues(headerName, out values)) {
                            SecurityHeaders[headerName] = string.Join(",", values);
                        } else {
                            MissingSecurityHeaders.Add(headerName);
                        }
                    }
                    if (!HstsPresent) {
                        HstsPresent = SecurityHeaders.TryGetValue("Strict-Transport-Security", out hstsHeader);
                    }
                    XssProtectionPresent = SecurityHeaders.ContainsKey("X-XSS-Protection");
                    ExpectCtPresent = SecurityHeaders.ContainsKey("Expect-CT");
                }
                if (hstsHeader != null) {
                    ParseHsts(hstsHeader);
                }
                if (hpkpHeader != null) {
                    PublicKeyPinsHeader = hpkpHeader;
                    PublicKeyPinsPresent = true;
                    ParseHpkp(hpkpHeader);
                    logger?.WriteWarning("Public-Key-Pins header is deprecated and should not be used.");
                } else if (collectHeaders && SecurityHeaders.TryGetValue("Public-Key-Pins", out var hdr)) {
                    PublicKeyPinsHeader = hdr;
                    PublicKeyPinsPresent = true;
                    ParseHpkp(hdr);
                    logger?.WriteWarning("Public-Key-Pins header is deprecated and should not be used.");
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

        private void ParseHpkp(string headerValue) {
            PublicKeyPinsMaxAge = 0;
            PublicKeyPinsIncludesSubDomains = false;
            PublicKeyPinsValid = false;
            PublicKeyPins.Clear();
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            var parts = headerValue.Split(';');
            var valid = true;
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("pin-sha256=\"", StringComparison.OrdinalIgnoreCase) && trimmed.EndsWith("\"")) {
                    var b64 = trimmed.Substring(12, trimmed.Length - 13);
                    PublicKeyPins.Add(b64);
                    try {
                        var bytes = Convert.FromBase64String(b64);
                        if (bytes.Length != 32) {
                            valid = false;
                        }
                    } catch (FormatException) {
                        valid = false;
                    }
                } else if (trimmed.StartsWith("max-age=", StringComparison.OrdinalIgnoreCase)) {
                    var value = trimmed.Substring(8);
                    if (int.TryParse(value, out var ma)) {
                        PublicKeyPinsMaxAge = ma;
                    }
                } else if (string.Equals(trimmed, "includeSubDomains", StringComparison.OrdinalIgnoreCase)) {
                    PublicKeyPinsIncludesSubDomains = true;
                }
            }
            PublicKeyPinsValid = valid && PublicKeyPins.Count >= 2;
        }

        /// <summary>
        /// Convenience method to check a URL with default logging.
        /// </summary>
        /// <param name="url">The URL to check.</param>
        /// <param name="checkHsts">Whether to check for HSTS.</param>
        /// <param name="collectHeaders">Whether to collect common security headers.</param>
        /// <param name="captureBody">Whether to capture the response body.</param>
        /// <returns>A populated <see cref="HttpAnalysis"/> instance.</returns>
        public static async Task<HttpAnalysis> CheckUrl(string url, bool checkHsts = false, bool collectHeaders = false, bool captureBody = false) {
            var analysis = new HttpAnalysis();
            await analysis.AnalyzeUrl(url, checkHsts, new InternalLogger(), collectHeaders, captureBody);
            return analysis;
        }
    }
}