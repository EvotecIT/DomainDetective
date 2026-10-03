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

            foreach (var part in ReachableSpfTerms(parts))
            {
                var token = part.Trim('"');
                if (token.Length > 0 && "+-~?".IndexOf(token[0]) >= 0) token = token.Substring(1);
                bool include = token.StartsWith("include:", StringComparison.OrdinalIgnoreCase);
                bool redirect = token.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase);
                if (!include && !redirect) continue;
                string target = token.Substring(include ? 8 : 9);
                if (target.Length == 0 || target.IndexOf('%') >= 0 || !visited.Add(target)) continue;
                try {
                    var child = await ResolveSpfRecordForCounting(target, logger, include ? "include" : "redirect");
                    if (!string.IsNullOrWhiteSpace(child)) {
                        await CollectMechanismsAsync(target, child!, new List<string>(path) { target }, depth + 1, visited, logger);
                    }
                } finally {
                    visited.Remove(target);
                }
            }
        }
    }
}
