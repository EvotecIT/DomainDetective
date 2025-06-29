using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml.Linq;

namespace DomainDetective.Reports;

/// <summary>Parser for zipped DMARC feedback reports.</summary>
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
            string domain = record.Element("identifiers")?.Element("header_from")?.Value ?? string.Empty;
            if (string.IsNullOrEmpty(domain)) {
                continue;
            }
            if (!table.TryGetValue(domain, out var summary)) {
                summary = new DmarcFeedbackSummary { Domain = domain };
                table.Add(domain, summary);
            }
            bool pass = string.Equals(record.Element("row")?.Element("policy_evaluated")?.Element("dkim")?.Value, "pass", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(record.Element("row")?.Element("policy_evaluated")?.Element("spf")?.Value, "pass", StringComparison.OrdinalIgnoreCase);
            if (pass) {
                summary.PassCount++;
            } else {
                summary.FailCount++;
            }
        }
        foreach (var item in table.Values.OrderBy(s => s.Domain)) {
            yield return item;
        }
    }
}
