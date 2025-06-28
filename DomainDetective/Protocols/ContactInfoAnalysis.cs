using DnsClientX;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Parses and validates contact TXT records.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class ContactInfoAnalysis {
    public string? ContactRecord { get; private set; }
    public bool RecordExists { get; private set; }
    public Dictionary<string, string> Fields { get; } = new();

    /// <summary>
    /// Processes TXT records to extract contact information.
    /// </summary>
    public async Task AnalyzeContactRecords(IEnumerable<DnsAnswer> dnsResults, InternalLogger logger) {
        await Task.Yield();

        ContactRecord = null;
        RecordExists = false;
        Fields.Clear();

        if (dnsResults == null) {
            logger?.WriteVerbose("DNS query returned no results.");
            return;
        }

        var recordList = dnsResults.ToList();
        RecordExists = recordList.Any();
        if (!RecordExists) {
            logger?.WriteVerbose("No contact record found.");
            return;
        }

        ContactRecord = string.Join(" ", recordList.Select(r => r.Data));
        logger?.WriteVerbose($"Analyzing contact TXT record {ContactRecord}");

        foreach (var part in (ContactRecord ?? string.Empty).Split(';')) {
            var kv = part.Split(new[] { '=' }, 2);
            if (kv.Length == 2) {
                Fields[kv[0].Trim().ToLowerInvariant()] = kv[1].Trim();
            }
        }
    }
}
