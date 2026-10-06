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
            var list = new List<TlsRptSummary>();
            var report = TlsRptReportParser.Parse(path);
            foreach (var p in report.Policies)
            {
                var entry = new TlsRptSummary
                {
                    MxHost = p.Policy.MxHost,
                    MxHostPatterns = new List<string>(p.Policy.MxHostPatterns),
                    PolicyDomain = p.Policy.PolicyDomain,
                    SuccessfulSessions = p.Summary.SuccessfulSessionCount,
                    FailedSessions = p.Summary.FailedSessionCount,
                    FailureByType = new System.Collections.Generic.Dictionary<string,int>(System.StringComparer.OrdinalIgnoreCase)
                };

                foreach (var fd in p.FailureDetails)
                {
                    string resultType = string.IsNullOrWhiteSpace(fd.ResultType) ? "unknown" : fd.ResultType;
                    int cnt = fd.FailedSessionCount;
                    entry.FailureByType[resultType] = (entry.FailureByType.TryGetValue(resultType, out var prev) ? prev : 0) + cnt;
                }

                list.Add(entry);
            }

            return list;
        }


    }

    /// <summary>Summarized statistics for a TLSRPT policy.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public sealed class TlsRptSummary {
        /// <summary>First policy MX pattern for legacy scalar consumers; not an observed receiving host.</summary>
        public string MxHost { get; set; } = null!;
        /// <summary>All policy MX patterns. Session counts cover the policy once.</summary>
        public List<string> MxHostPatterns { get; set; } = new();
        /// <summary>Domain covered by this policy summary.</summary>
        public string? PolicyDomain { get; set; }
        /// <summary>Count of successful TLS sessions.</summary>
        public int SuccessfulSessions { get; set; }
        /// <summary>Count of failed TLS sessions.</summary>
        public int FailedSessions { get; set; }
        /// <summary>Optional breakdown of failures by type (result-type).</summary>
        public System.Collections.Generic.Dictionary<string,int> FailureByType { get; set; } = new System.Collections.Generic.Dictionary<string,int>(System.StringComparer.OrdinalIgnoreCase);
    }
}
