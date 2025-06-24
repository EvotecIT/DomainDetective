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
        /// <summary>Gets a collection of detected security headers.</summary>
        public Dictionary<string, string> SecurityHeaders { get; } = new();
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
            "Permissions-Policy"
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
                if (checkHsts) {
                    HstsPresent = response.Headers.Contains("Strict-Transport-Security");
                }
                if (collectHeaders) {
                    foreach (var headerName in _securityHeaderNames) {
                        if (response.Headers.TryGetValues(headerName, out var values) ||
                            response.Content.Headers.TryGetValues(headerName, out values)) {
                            SecurityHeaders[headerName] = string.Join(",", values);
                        }
                    }
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