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
            var list = new List<TlsRptSummary>();
            if (!doc.RootElement.TryGetProperty("policies", out var policies) || policies.ValueKind != JsonValueKind.Array) {
                return list;
            }
            foreach (var policy in policies.EnumerateArray()) {
                var mxHost = string.Empty;
                if (policy.TryGetProperty("policy", out var pol) && pol.TryGetProperty("mx-host", out var mx)) {
                    mxHost = mx.GetString() ?? string.Empty;
                }
                int success = 0;
                int failure = 0;
                if (policy.TryGetProperty("summary", out var summary)) {
                    if (summary.TryGetProperty("total-successful-session-count", out var s)) {
                        success = s.GetInt32();
                    }
                    if (summary.TryGetProperty("total-failure-session-count", out var f)) {
                        failure = f.GetInt32();
                    }
                }
                list.Add(new TlsRptSummary {
                    MxHost = mxHost,
                    SuccessfulSessions = success,
                    FailedSessions = failure
                });
            }
            return list;
        }
    }

    /// <summary>Summarized statistics for a TLSRPT policy.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class TlsRptSummary {
        /// <summary>Hostname of the receiving MX.</summary>
        public string MxHost { get; set; }
        /// <summary>Count of successful TLS sessions.</summary>
        public int SuccessfulSessions { get; set; }
        /// <summary>Count of failed TLS sessions.</summary>
        public int FailedSessions { get; set; }
    }
}
