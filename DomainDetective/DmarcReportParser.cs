using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml.Linq;
using System.Globalization;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Parser for zipped DMARC feedback reports.
/// Handles internationalized domains and computes pass/fail counts.
/// </summary>
public static class DmarcReportParser {
    /// <summary>Parses the specified zip file and returns per-domain statistics.</summary>
    /// <param name="path">Path to the zipped XML feedback report.</param>
    public static IEnumerable<DmarcFeedbackSummary> ParseZip(string path) {
        using var archive = ZipFile.OpenRead(path);
        var entry = archive.Entries.FirstOrDefault(e => e.FullName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase));
        if (entry == null) {
            yield break;
        }

        using var stream = entry.Open();
        XDocument doc = XDocument.Load(stream);
        var table = new Dictionary<string, DmarcFeedbackSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in doc.Descendants("record")) {
            string header = record.Element("identifiers")?.Element("header_from")?.Value ?? string.Empty;
            if (string.IsNullOrEmpty(header)) {
                continue;
            }

            string domain;
            try {
                domain = DomainHelper.ValidateIdn(header);
            } catch (ArgumentException) {
                continue;
            }

            if (!table.TryGetValue(domain, out var summary)) {
                summary = new DmarcFeedbackSummary { Domain = domain };
                table[domain] = summary;
            }

            // Extract disposition and message count
            string disposition = record.Element("row")?.Element("policy_evaluated")?.Element("disposition")?.Value ?? string.Empty;
            string dkim = record.Element("row")?.Element("policy_evaluated")?.Element("dkim")?.Value ?? string.Empty;
            string spf = record.Element("row")?.Element("policy_evaluated")?.Element("spf")?.Value ?? string.Empty;
            string countStr = record.Element("row")?.Element("count")?.Value ?? "1";
            if (!int.TryParse(countStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out int count)) {
                count = 1;
            }

            bool isPass = disposition.Equals("none", StringComparison.OrdinalIgnoreCase)
                || (dkim.Equals("pass", StringComparison.OrdinalIgnoreCase)
                    && (string.IsNullOrEmpty(spf) || spf.Equals("pass", StringComparison.OrdinalIgnoreCase)));

            if (isPass) {
                summary.PassCount += count;
            } else {
                summary.FailCount += count;
            }
        }

        foreach (var summary in table.Values) {
            yield return summary;
        }
    }

    /// <summary>
    /// Parses multiple zipped DMARC reports and aggregates the results by domain.
    /// </summary>
    /// <param name="paths">Paths to zipped XML feedback reports.</param>
    public static IEnumerable<DmarcFeedbackSummary> ParseMultiple(IEnumerable<string> paths) {
        var aggregated = new Dictionary<string, DmarcFeedbackSummary>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in paths) {
            foreach (var summary in ParseZip(path)) {
                if (!aggregated.TryGetValue(summary.Domain, out var existing)) {
                    aggregated[summary.Domain] = summary;
                } else {
                    existing.PassCount += summary.PassCount;
                    existing.FailCount += summary.FailCount;
                }
            }
        }

        return aggregated.Values.OrderBy(s => s.Domain, StringComparer.OrdinalIgnoreCase);
    }
}