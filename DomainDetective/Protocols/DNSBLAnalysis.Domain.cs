using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DNSBLAnalysis {
        private static readonly List<DnsblEntry> _domainBlockLists = new();

        internal List<string> DomainDNSBLLists => _domainBlockLists
            .Where(e => e.Enabled)
            .Select(e => e.Domain)
            .ToList();

        public async IAsyncEnumerable<DNSBLRecord> AnalyzeDomainBlocklists(string domain, InternalLogger logger) {
            Reset();
            Logger = logger;
            Logger?.WriteVerbose($"Checking {domain} against {DomainDNSBLLists.Count} domain blocklists");
            var collected = new List<DNSBLRecord>();
            await foreach (var record in QueryDNSBL(DomainDNSBLLists, domain)) {
                collected.Add(record);
                yield return record;
            }
            ConvertToResults(domain, collected);
        }

        public async Task<bool> IsDomainListedAsync(string domain, InternalLogger logger) {
            await ToListAsync(AnalyzeDomainBlocklists(domain, logger));
            return Results.TryGetValue(domain, out var result) && result.IsBlacklisted;
        }
    }
}
