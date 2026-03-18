using System;
using System.Collections.Generic;
using System.Linq;
using DomainDetective.Reports;

namespace DomainDetective.Tests.Reports
{
    internal static class ParityAssert
    {
        public static void EqualExecRows(IReadOnlyList<ExecutiveSummaryBuilder.Row> a, IReadOnlyList<ExecutiveSummaryBuilder.Row> b)
        {
            var byDomainA = a.ToDictionary(x => x.Domain, StringComparer.OrdinalIgnoreCase);
            var byDomainB = b.ToDictionary(x => x.Domain, StringComparer.OrdinalIgnoreCase);
            var allDomains = byDomainA.Keys.Union(byDomainB.Keys, StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList();

            var diffs = new List<string>();
            foreach (var d in allDomains)
            {
                if (!byDomainA.TryGetValue(d, out var ra)) { diffs.Add($"[-] Missing in A: {d}"); continue; }
                if (!byDomainB.TryGetValue(d, out var rb)) { diffs.Add($"[-] Missing in B: {d}"); continue; }
                CompareField(d, "MX", ra.Mx, rb.Mx, diffs);
                CompareField(d, "SPF", ra.Spf, rb.Spf, diffs);
                CompareField(d, "DKIM", ra.Dkim, rb.Dkim, diffs);
                CompareField(d, "DMARC", ra.Dmarc, rb.Dmarc, diffs);
                CompareField(d, "MTA-STS", ra.Mtasts, rb.Mtasts, diffs);
                CompareField(d, "TLS-RPT", ra.TlsRpt, rb.TlsRpt, diffs);
                CompareField(d, "Microsoft365Workloads", ra.Microsoft365Workloads, rb.Microsoft365Workloads, diffs);
                CompareField(d, "Classification", ra.Classification, rb.Classification, diffs);
                CompareField(d, "Warnings", ra.Warnings.ToString(), rb.Warnings.ToString(), diffs);
                CompareField(d, "Errors", ra.Errors.ToString(), rb.Errors.ToString(), diffs);
            }

            if (diffs.Count > 0)
            {
                var msg = "Parity mismatch:\n" + string.Join("\n", diffs);
                throw new Xunit.Sdk.XunitException(msg);
            }
        }

        private static void CompareField(string domain, string field, string? a, string? b, List<string> diffs)
        {
            if (!string.Equals(a ?? string.Empty, b ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                diffs.Add($"[!] {domain} {field}: '{a}' != '{b}'");
            }
        }
    }
}

