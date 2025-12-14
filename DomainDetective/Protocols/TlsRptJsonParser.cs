using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace DomainDetective {
    /// <summary>Parses SMTP TLS Reporting (TLSRPT) JSON reports.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public static class TlsRptJsonParser {
        /// <summary>Reads a TLSRPT report from disk.</summary>
        /// <param name="path">Path to the JSON file.</param>
        /// <returns>Enumerable of summary results.</returns>
        public static IEnumerable<TlsRptSummary> ParseReport(string path) {
            var json = File.ReadAllText(path);
            using var doc = JsonDocument.Parse(json);

            ValidateSchema(doc.RootElement);

            var list = new List<TlsRptSummary>();
            var policies = doc.RootElement.GetProperty("policies");

            foreach (var policy in policies.EnumerateArray()) {
                var pol = policy.GetProperty("policy");
                var mxHost = pol.GetProperty("mx-host").GetString() ?? string.Empty;
                var summary = policy.GetProperty("summary");
                int success = summary.GetProperty("total-successful-session-count").GetInt32();
                int failure = summary.GetProperty("total-failure-session-count").GetInt32();

                var entry = new TlsRptSummary {
                    MxHost = mxHost,
                    SuccessfulSessions = success,
                    FailedSessions = failure,
                    FailureByType = new System.Collections.Generic.Dictionary<string,int>(System.StringComparer.OrdinalIgnoreCase)
                };

                if (policy.TryGetProperty("failure-details", out var details) && details.ValueKind == JsonValueKind.Array)
                {
                    foreach (var fd in details.EnumerateArray())
                    {
                        string resultType = fd.TryGetProperty("result-type", out var rt) ? (rt.GetString() ?? "unknown") : "unknown";
                        int cnt = fd.TryGetProperty("failed-session-count", out var fc) ? fc.GetInt32() : 0;
                        entry.FailureByType[resultType] = (entry.FailureByType.TryGetValue(resultType, out var prev) ? prev : 0) + cnt;
                    }
                }

                list.Add(entry);
            }

            return list;
        }

        private static void ValidateSchema(JsonElement root) {
            if (!root.TryGetProperty("organization-name", out _)) {
                throw new FormatException("Missing organization-name field.");
            }
            if (!root.TryGetProperty("date-range", out var range)
                || !range.TryGetProperty("start-datetime", out _)
                || !range.TryGetProperty("end-datetime", out _)) {
                throw new FormatException("Missing date-range fields.");
            }
            if (!root.TryGetProperty("report-id", out _)) {
                throw new FormatException("Missing report-id field.");
            }
            if (!root.TryGetProperty("policies", out var policies) || policies.ValueKind != JsonValueKind.Array) {
                throw new FormatException("Missing policies array.");
            }

            foreach (var policy in policies.EnumerateArray()) {
                if (!policy.TryGetProperty("policy", out var pol)
                    || !pol.TryGetProperty("policy-type", out _)
                    || !pol.TryGetProperty("mx-host", out _)) {
                    throw new FormatException("Invalid policy entry.");
                }
                if (!policy.TryGetProperty("summary", out var summary)
                    || !summary.TryGetProperty("total-successful-session-count", out _)
                    || !summary.TryGetProperty("total-failure-session-count", out _)) {
                    throw new FormatException("Invalid summary entry.");
                }
            }
        }
    }

    /// <summary>Summarized statistics for a TLSRPT policy.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class TlsRptSummary {
        /// <summary>Hostname of the receiving MX.</summary>
        public string MxHost { get; set; } = null!;
        /// <summary>Count of successful TLS sessions.</summary>
        public int SuccessfulSessions { get; set; }
        /// <summary>Count of failed TLS sessions.</summary>
        public int FailedSessions { get; set; }
        /// <summary>Optional breakdown of failures by type (result-type).</summary>
        public System.Collections.Generic.Dictionary<string,int> FailureByType { get; set; } = new System.Collections.Generic.Dictionary<string,int>(System.StringComparer.OrdinalIgnoreCase);
    }
}
