using System;
using System.Collections.Generic;
using System.Net.Http;

namespace DomainDetective {
    public partial class HttpAnalysis {
        private void ApplyRequestHeaders(HttpRequestMessage request, HttpRequestOptions requestOptions) {
            if (request == null) {
                throw new ArgumentNullException(nameof(request));
            }
            if (requestOptions == null) {
                throw new ArgumentNullException(nameof(requestOptions));
            }

            try {
                if (!string.IsNullOrWhiteSpace(requestOptions.Cookie)) {
                    request.Headers.TryAddWithoutValidation("Cookie", requestOptions.Cookie);
                    if (!RequestHeaderNames.Contains("Cookie")) {
                        RequestHeaderNames.Add("Cookie");
                    }
                }

                if (requestOptions.Headers != null && requestOptions.Headers.Count > 0) {
                    foreach (var kv in requestOptions.Headers) {
                        if (string.IsNullOrWhiteSpace(kv.Key)) {
                            continue;
                        }

                        request.Headers.TryAddWithoutValidation(kv.Key, kv.Value ?? string.Empty);
                        if (!RequestHeaderNames.Contains(kv.Key)) {
                            RequestHeaderNames.Add(kv.Key);
                        }
                    }
                }
            } catch {
                // Best-effort; invalid header names/values should not fail analysis.
            }
        }

        private static void CaptureNamedHeaders(HttpResponseMessage response, IEnumerable<string> names, Dictionary<string, string> target) {
            if (response == null || names == null || target == null) {
                return;
            }

            foreach (var name in names) {
                try {
                    if (string.IsNullOrWhiteSpace(name)) {
                        continue;
                    }

                    if (response.Headers.TryGetValues(name, out var values) ||
                        response.Content.Headers.TryGetValues(name, out values)) {
                        target[name] = string.Join(",", values);
                    }
                } catch {
                }
            }
        }

        private void ParseHsts(string headerValue) {
            HstsMaxAge = null;
            HstsIncludesSubDomains = false;
            HstsPreloadDirectivePresent = false;
            UnknownHstsDirectives = new List<string>();
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
                    } else if (!UnknownHstsDirectives.Contains(trimmed)) {
                        UnknownHstsDirectives.Add(trimmed);
                    }
                } else if (trimmed.Equals("includesubdomains", StringComparison.OrdinalIgnoreCase)) {
                    HstsIncludesSubDomains = true;
                } else if (trimmed.Equals("preload", StringComparison.OrdinalIgnoreCase)) {
                    HstsPreloadDirectivePresent = true;
                } else if (!string.IsNullOrEmpty(trimmed) && !UnknownHstsDirectives.Contains(trimmed)) {
                    UnknownHstsDirectives.Add(trimmed);
                }
            }

            HstsTooShort = HstsMaxAge.HasValue && HstsMaxAge.Value < 10886400;
            HstsPreloadEligible = HstsPreloadDirectivePresent &&
                                  HstsIncludesSubDomains &&
                                  HstsMaxAge.HasValue &&
                                  HstsMaxAge.Value >= 31536000;
        }

        private void ParseContentSecurityPolicy(string headerValue) {
            CspUnsafeDirectives = false;
            CspFrameAncestorsPresent = false;
            if (string.IsNullOrEmpty(headerValue)) {
                return;
            }

            var parts = headerValue.Split(';');
            foreach (var part in parts) {
                var trimmed = part.Trim();
                if (trimmed.StartsWith("frame-ancestors", StringComparison.OrdinalIgnoreCase)) {
                    CspFrameAncestorsPresent = true;
                }
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

#if NET8_0_OR_GREATER
        private static string? ParseQuicVersion(string? headerValue) {
            if (string.IsNullOrEmpty(headerValue)) {
                return null;
            }

            var entries = headerValue.Split(',');
            foreach (var entry in entries) {
                var trimmed = entry.Trim();
                if (trimmed.StartsWith("h3", StringComparison.OrdinalIgnoreCase) ||
                    trimmed.StartsWith("quic", StringComparison.OrdinalIgnoreCase)) {
                    var eq = trimmed.IndexOf('=');
                    return eq > 0 ? trimmed.Substring(0, eq) : trimmed;
                }
            }

            return null;
        }
#endif
    }
}
