using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective
{
    public partial class SpfAnalysis
    {
        /// <summary>
        /// Populates <see cref="SpfPartAnalyses"/> with provenance by traversing include/redirect chains.
        /// </summary>
        /// <param name="domain">Base domain whose SPF record is being analyzed.</param>
        /// <param name="logger">Optional logger for diagnostics.</param>
        public async Task PopulateProvenanceAsync(string domain, InternalLogger? logger = null)
        {
            SpfPartAnalyses = new List<SpfPartAnalysis>();
            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrWhiteSpace(SpfRecord)) return;
            await CollectMechanismsAsync(domain, SpfRecord, new List<string>(), 0, visited, logger);
        }

        private async Task CollectMechanismsAsync(string domain, string record, List<string> path, int depth, HashSet<string> visited, InternalLogger? logger)
        {
            if (depth > 20) return;
            var parts = TokenizeSpfRecord(record).ToArray();
            foreach (var part in parts)
            {
                // Populate provenance and resolved collections without mutating top-level lists
                AddPartToResolvedLists(part, logger, domain, depth, path);
            }

            foreach (var part in parts)
            {
                var token = part.Trim('"');
                if (token.StartsWith("include:", StringComparison.OrdinalIgnoreCase))
                {
                    var inc = token.Substring(8);
                    if (string.IsNullOrWhiteSpace(inc)) continue;
                    if (!visited.Add(inc)) continue;
                    string? includeRecord = null;
                    if (TestSpfRecords.TryGetValue(inc, out var fake))
                    {
                        includeRecord = fake;
                    }
                    else
                    {
                        var answers = await DnsConfiguration.QueryDNS(
                            inc,
                            DnsRecordType.TXT,
                            "SPF1",
                            includeAliasesInFilter: true);
                        if (answers != null && answers.Length > 0) includeRecord = answers[0].Data;
                    }
                    if (!string.IsNullOrWhiteSpace(includeRecord))
                    {
                        var next = new List<string>(path) { inc };
                        await CollectMechanismsAsync(inc, includeRecord!, next, depth + 1, visited, logger);
                    }
                    visited.Remove(inc);
                }
                else if (token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
                {
                    var redir = token.Substring(9);
                    if (string.IsNullOrWhiteSpace(redir)) continue;
                    string? redirectRecord = null;
                    if (TestSpfRecords.TryGetValue(redir, out var fakeR)) redirectRecord = fakeR;
                    else
                    {
                        var answers = await DnsConfiguration.QueryDNS(
                            redir,
                            DnsRecordType.TXT,
                            "SPF1",
                            includeAliasesInFilter: true);
                        if (answers != null && answers.Length > 0) redirectRecord = answers[0].Data;
                    }
                    if (!string.IsNullOrWhiteSpace(redirectRecord))
                    {
                        var next = new List<string>(path) { redir };
                        await CollectMechanismsAsync(redir, redirectRecord!, next, depth + 1, visited, logger);
                    }
                }
            }
        }
    }
}
