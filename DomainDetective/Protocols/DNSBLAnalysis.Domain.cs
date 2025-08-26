using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides domain-based DNS block list analysis functionality.
    /// </summary>
    public partial class DNSBLAnalysis {
        private static readonly List<DnsblEntry> _domainBlockLists = new();

        /// <summary>
        /// Gets the list of enabled domain based DNS block lists.
        /// </summary>
        internal List<string> DomainDNSBLLists => _domainBlockLists
            .Where(e => e.Enabled)
            .Select(e => e.Domain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        /// <summary>
        /// Queries all configured domain block lists for the specified domain.
        /// </summary>
        /// <param name="domain">Domain name to test.</param>
        /// <param name="logger">Instance used to log progress.</param>
        /// <returns>Enumerable of individual DNSBL records.</returns>
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

        /// <summary>
        /// Queries domain block lists for multiple domains in parallel and aggregates results.
        /// </summary>
        /// <param name="domains">Domain names to test.</param>
        /// <param name="logger">Instance used to log progress.</param>
        /// <param name="clearExisting">Whether to clear previous results.</param>
        public async Task AnalyzeDomainBlocklistsMany(IEnumerable<string> domains, InternalLogger logger, bool clearExisting = true) {
            if (domains == null) return;
            var items = domains.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (clearExisting) {
                Reset();
            }
            Logger = logger;
            if (items.Count == 0) return;

            Logger?.WriteVerbose($"Checking {items.Count} domain(s) against {DomainDNSBLLists.Count} domain blocklists (parallel)…");

            var tasks = new List<Task<(string key, List<DNSBLRecord> records)>>();
            foreach (var domain in items) {
                var d = domain; // capture
                tasks.Add(Task.Run(async () => {
                    var list = new List<DNSBLRecord>();
                    await foreach (var record in QueryDNSBL(DomainDNSBLLists, d)) {
                        list.Add(record);
                    }
                    return (d, list);
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var (key, records) in results) {
                ConvertToResults(key, records);
            }
        }

        /// <summary>
        /// Determines whether the domain appears on any configured domain block list.
        /// </summary>
        /// <param name="domain">Domain name to test.</param>
        /// <param name="logger">Instance used to log progress.</param>
        /// <returns><c>true</c> if the domain is listed; otherwise <c>false</c>.</returns>
        public async Task<bool> IsDomainListedAsync(string domain, InternalLogger logger) {
            await ToListAsync(AnalyzeDomainBlocklists(domain, logger));
            return Results.TryGetValue(domain, out var result) && result.IsBlacklisted;
        }
    }
}
