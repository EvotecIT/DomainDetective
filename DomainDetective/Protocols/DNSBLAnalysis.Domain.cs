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
        private static readonly object _domainListLock = new();

        /// <summary>
        /// Gets the list of enabled domain based DNS block lists.
        /// </summary>
        internal List<string> DomainDNSBLLists {
            get {
                lock (_domainListLock) {
                    return _domainBlockLists
                        .Where(e => e != null && e.Enabled && !string.IsNullOrWhiteSpace(e.Domain))
                        .Select(e => e.Domain)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                }
            }
        }

        /// <summary>
        /// Queries all configured domain block lists for the specified domain.
        /// </summary>
        /// <param name="domain">Domain name to test.</param>
        /// <param name="logger">Instance used to log progress.</param>
        /// <returns>Enumerable of individual DNSBL records.</returns>
        public async IAsyncEnumerable<DNSBLRecord> AnalyzeDomainBlocklists(string domain, InternalLogger logger) {
            Reset();
            using var run = BeginQueryRun(default);
            Subject = domain;
            logger?.WriteVerbose($"Checking {domain} against {DomainDNSBLLists.Count} domain blocklists");
            var collected = new List<DNSBLRecord>();
            await foreach (var record in QueryDNSBL(DomainDNSBLLists, domain, run, DnsblIpSource.Domain, sourceHost: domain)) {
                collected.Add(record);
                yield return record;
            }
            ConvertToResults(domain, collected, logger);
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
            if (items.Count == 0) return;
            using var run = BeginQueryRun(default);

            logger?.WriteVerbose($"Checking {items.Count} domain(s) against {DomainDNSBLLists.Count} domain blocklists (parallel)…");

            var results = await Helpers.BoundedAsync.RunAsync(items, async d => {
                    var list = new List<DNSBLRecord>();
                    await foreach (var record in QueryDNSBL(DomainDNSBLLists, d, run, DnsblIpSource.Domain, sourceHost: d)) {
                        list.Add(record);
                    }
                    return (d, list);
            }, 16, run.CallerToken);
            foreach (var (key, records) in results) {
                ConvertToResults(key, records, logger);
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
