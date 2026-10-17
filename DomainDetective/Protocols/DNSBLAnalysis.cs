using DnsClientX;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Provides routines to query DNS block lists for a host.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Both IP- and domain-based blacklists are supported. Results include
    /// detailed reply codes for further interpretation.
    /// </remarks>
    public partial class DNSBLAnalysis : IHasAssessments {
        /// <summary>Serializes retained evidence publication and synchronous projections across overlapping append runs.</summary>
        internal object SyncRoot { get; } = new();
        /// <summary>Subject for this analysis when domain-scoped; null for multi-input or IP-only runs.</summary>
        public string? Subject { get; set; }
        /// <summary>Gets or sets the dns configuration value.</summary>
        public DnsConfiguration DnsConfiguration { get; set; }

        /// <summary>Optional override for DNS queries used for testing.</summary>
        /// <remarks>This legacy callback has no cancellation token. Its owner must complete admitted work; query deadlines stop waiting for it. Use DnsConfiguration.QueryDnsResponseOverride for owned, cooperative cancellation.</remarks>
        public Func<string[], DnsRecordType, Task<IEnumerable<DnsResponse>>>? QueryDnsFullOverride { private get; set; }

        private static readonly List<DnsblEntry> _defaultEntries = new();
        private static readonly List<DnsblEntry> _defaultDomainBlockLists = new();
        private static readonly List<BlockListEntry> _defaultIpBlockLists = new();
        private static Dictionary<string, Dictionary<string, (bool IsListed, string Meaning)>> _providerReplyCodes = new(StringComparer.OrdinalIgnoreCase);
        private const string DefaultUpdateUrl = "https://raw.githubusercontent.com/EvotecIT/DomainDetective/master/Data/dnsbl.json";

        static DNSBLAnalysis() {
            try {
                using var stream = typeof(DNSBLAnalysis).Assembly.GetManifestResourceStream("DomainDetective.dnsbl.json");
                if (stream != null) {
                    using var reader = new StreamReader(stream);
                    var json = reader.ReadToEnd();
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var config = JsonSerializer.Deserialize<DnsblConfiguration>(json, options);
                    if (config != null) {
                        if (config.Providers != null) {
                            foreach (var provider in config.Providers) {
                                _defaultEntries.Add(provider);
                                if (provider.ReplyCodes?.Count > 0) {
                                    _providerReplyCodes[provider.Domain] = provider.ReplyCodes.ToDictionary(
                                        c => c.Key,
                                        c => (c.Value.IsListed, c.Value.Meaning),
                                        StringComparer.OrdinalIgnoreCase);
                                }
                            }
                        }
                        if (config.DomainBlockLists != null) {
                            var domainBlockLists = config.DomainBlockLists
                                .Where(e => e != null && !string.IsNullOrWhiteSpace(e.Domain))
                                .Select(e => new DnsblEntry(e.Domain, e.Enabled, e.Comment, e.Port))
                                .ToList();
                            if (domainBlockLists.Count > 0) {
                                _defaultDomainBlockLists.AddRange(domainBlockLists);
                                lock (_domainListLock) {
                                    _domainBlockLists.AddRange(domainBlockLists.Select(e =>
                                        new DnsblEntry(e.Domain, e.Enabled, e.Comment, e.Port)));
                                }
                            }
                        }
                        if (config.IpBlockLists != null) {
                            _defaultIpBlockLists.AddRange(config.IpBlockLists);
                        }
                    }
                }
            } catch (Exception ex) {
                // If loading embedded resource fails, initialize with empty collections
                // The lists can be populated later using LoadDNSBL or UpdateDNSBL methods
                System.Diagnostics.Debug.WriteLine($"Failed to load embedded DNSBL config: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the collection of configured DNSBL provider entries.
        /// Use <see cref="AddDNSBL(string, bool, string?, int)"/>, <see cref="RemoveDNSBL(string)"/>,
        /// <see cref="ClearDNSBL()"/>, <see cref="LoadDNSBL(string, bool)"/> or
        /// <see cref="LoadDnsblConfig(string, bool, bool)"/> to modify the list.
        /// </summary>
        /// <value>
        /// The DNSBL provider entries.
        /// </value>
        internal List<DnsblEntry> DnsblEntries { get; } = new();

        /// <summary>Initializes a new instance of the DNSBLAnalysis class.</summary>
        public DNSBLAnalysis(DnsConfiguration? dnsConfiguration = null) {
            DnsConfiguration = dnsConfiguration ?? new DnsConfiguration();
            DnsblEntries.AddRange(_defaultEntries.Select(e => {
                var entry = new DnsblEntry(e.Domain, e.Enabled, e.Comment, e.Port);
                if (e.ReplyCodes?.Count > 0) {
                    entry.ReplyCodes = new Dictionary<string, DnsblReplyCode>(e.ReplyCodes, StringComparer.OrdinalIgnoreCase);
                }
                return entry;
            }));
            foreach (var entry in _defaultIpBlockLists) {
                BlockLists.Entries.Add(new BlockListEntry {
                    Name = entry.Name,
                    Url = entry.Url,
                    Enabled = entry.Enabled,
                    Comment = entry.Comment
                });
            }
        }

        internal List<string> DNSBLLists => DnsblEntries
            .Where(e => e.Enabled)
            .Select(e => e.Domain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        /// <summary>Gets a value indicating whether any query returned a listing.</summary>
        public bool IsBlacklisted => GetCoverageResults().Values.Any(result => result.IsBlacklisted);
        /// <summary>Gets the number of hosts or addresses checked.</summary>
        public int RecordChecked => GetCoverageResults().Count;
        /// <summary>Gets the count of hosts that were listed.</summary>
        public int Blacklisted => GetCoverageResults().Values.Count(result => result.IsBlacklisted);
        /// <summary>Gets the count of hosts that were not listed.</summary>
        public int NotBlacklisted => GetCoverageResults().Values.Count(result => !result.IsBlacklisted && result.NotChecked == 0);

        /// <summary>Gets the per-host DNSBL query results.</summary>
        public Dictionary<string, DNSQueryResult> Results { get; set; } = new Dictionary<string, DNSQueryResult>(StringComparer.OrdinalIgnoreCase);

        /// <summary>Gets a flattened list of all DNSBL records returned.</summary>
        public List<DNSBLRecord> AllResults { get; private set; } = new List<DNSBLRecord>();
        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();

        /// <summary>
        /// Clears cached results allowing the instance to be reused.
        /// </summary>
        public void Reset() {
            lock (SyncRoot) {
                Results = new Dictionary<string, DNSQueryResult>(StringComparer.OrdinalIgnoreCase);
                AllResults = new List<DNSBLRecord>();
                Subject = null;
                Assessments.Clear();
                DiscoverySucceeded = true;
                DiscoveryErrors.Clear();
                _failedDiscoverySources.Clear();

            }
        }

        internal async Task AnalyzeDNSBLRecordsMX(string domainName, InternalLogger logger, bool clearExisting = true, DomainIpScanMode scanMode = DomainIpScanMode.MxThenApexFallback, System.Threading.CancellationToken cancellationToken = default, QueryRun? queryRun = null) {
            if (clearExisting) { Reset(); }
            Subject = domainName;
            using var ownedRun = queryRun == null ? BeginQueryRun(cancellationToken) : null;
            var run = queryRun ?? ownedRun!;
            var domainRecordsReady = new TaskCompletionSource<Task<List<DNSBLRecord>>>(TaskCreationOptions.RunContinuationsAsynchronously);
            int domainStarted = 0;
            async Task<List<DNSBLRecord>> QueryDomainAsync() {
                run.CallerToken.ThrowIfCancellationRequested();
                return await ToListAsync(QueryDNSBL(DomainDNSBLLists, domainName, run, DnsblIpSource.Domain, sourceHost: domainName)).ConfigureAwait(false);
            }
            void StartDomainProviders() {
                if (System.Threading.Interlocked.CompareExchange(ref domainStarted, 1, 0) == 0) {
                    // Start synchronously after the first resolved target's provider work
                    // is queued, before later targets can fill the provider admission queue.
                    domainRecordsReady.TrySetResult(QueryDomainAsync());
                }
            }
            var ipRecords = DiscoverAndQueryTargetsAsync(domainName, scanMode, run, logger, StartDomainProviders);
            var domainRecords = domainRecordsReady.Task.Unwrap();
            // Observe both owned branches even if discovery or a provider callback fails.
            await Task.WhenAll(domainRecords, ipRecords).ConfigureAwait(false);
            ConvertToResults(domainName, await domainRecords, logger);
            foreach (var result in await ipRecords) { ConvertToResults(result.Ip, result.Records, logger); }
            cancellationToken.ThrowIfCancellationRequested();
            RecordSummary(logger, domainName);
        }
        /// <summary>
        /// Queries the configured DNSBL providers for the specified host or IP address.
        /// </summary>
        /// <param name="ipAddressOrHostname">Address or hostname to query.</param>
        /// <param name="logger">Logger for verbose output.</param>
        /// <returns>Enumeration of <see cref="DNSBLRecord"/> objects.</returns>
        public async IAsyncEnumerable<DNSBLRecord> AnalyzeDNSBLRecords(string ipAddressOrHostname, InternalLogger logger) {
            Reset();
            using var run = BeginQueryRun(default);
            logger?.WriteVerbose($"Checking {ipAddressOrHostname} against {DNSBLLists.Count} blacklists");
            var collected = new List<DNSBLRecord>();
            var isIp = System.Net.IPAddress.TryParse(ipAddressOrHostname, out _);
            DnsblIpSource? src = isIp ? DnsblIpSource.UserProvided : DnsblIpSource.Domain;
            string srcHost = isIp ? "UserProvided" : ipAddressOrHostname;
            await foreach (var record in QueryDNSBL(DNSBLLists, ipAddressOrHostname, run, src, sourceHost: srcHost)) {
                collected.Add(record);
                yield return record;
            }
            ConvertToResults(ipAddressOrHostname, collected, logger);
        }

        /// <summary>
        /// Queries DNSBL providers for multiple hosts/IPs in parallel and aggregates results.
        /// </summary>
        /// <param name="ipAddressesOrHostnames">Addresses or hostnames to query.</param>
        /// <param name="logger">Logger for verbose output.</param>
        /// <param name="clearExisting">Whether to clear accumulated results before adding.</param>
        public Task AnalyzeDNSBLRecordsMany(IEnumerable<string> ipAddressesOrHostnames, InternalLogger logger, bool clearExisting = true)
            => AnalyzeDNSBLRecordsMany(ipAddressesOrHostnames, logger, clearExisting, default);

        /// <summary>Queries multiple inputs with caller cancellation and a shared provider budget.</summary>
        public Task AnalyzeDNSBLRecordsMany(IEnumerable<string> ipAddressesOrHostnames, InternalLogger logger, bool clearExisting, System.Threading.CancellationToken cancellationToken)
            => AnalyzeDNSBLRecordsMany(ipAddressesOrHostnames, logger, clearExisting, cancellationToken, null);

        internal async Task AnalyzeDNSBLRecordsMany(IEnumerable<string> ipAddressesOrHostnames, InternalLogger logger, bool clearExisting, System.Threading.CancellationToken cancellationToken, QueryRun? queryRun) {
            if (ipAddressesOrHostnames == null) return;
            var items = ipAddressesOrHostnames.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (clearExisting) {
                Reset();
            }
            if (items.Count == 0) return;
            using var ownedRun = queryRun == null ? BeginQueryRun(cancellationToken) : null;
            var run = queryRun ?? ownedRun!;

            logger?.WriteVerbose($"Checking {items.Count} input(s) against {DNSBLLists.Count} blacklists (parallel)…");

            var results = await Helpers.BoundedAsync.RunAsync(items, async name => {
                    var list = new List<DNSBLRecord>();
                    var isIpInner = System.Net.IPAddress.TryParse(name, out _);
                    DnsblIpSource? srcInner = isIpInner ? DnsblIpSource.UserProvided : DnsblIpSource.Domain;
                    string srcHostInner = isIpInner ? "UserProvided" : name;
                    await foreach (var record in QueryDNSBL(DNSBLLists, name, run, srcInner, sourceHost: srcHostInner)) {
                        list.Add(record);
                    }
                    return (name, list);
            }, 16, run.CallerToken);
            foreach (var (key, records) in results) {
                ConvertToResults(key, records, logger);
            }

            cancellationToken.ThrowIfCancellationRequested();
            RecordSummary(logger);
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results, InternalLogger? logger) {
            var warnings = new List<(string Code, string Message)>();
            lock (SyncRoot) {
                DNSQueryResult queryResult = new DNSQueryResult {
                    Host = ipAddressOrHostname,
                    DNSBLRecords = results,
                };
                if (Results.ContainsKey(ipAddressOrHostname)) {
                    Results.Remove(ipAddressOrHostname);
                }
                Results[ipAddressOrHostname] = queryResult;
                AllResults.AddRange(results);
                bool incompleteCoverage = AllResults.Any(record => !record.QuerySucceeded &&
                    string.Equals(GetRecordTargetKey(record), ipAddressOrHostname, StringComparison.OrdinalIgnoreCase));
                bool retainedListing = AllResults.Any(record => record.IsBlackListed &&
                    string.Equals(GetRecordTargetKey(record), ipAddressOrHostname, StringComparison.OrdinalIgnoreCase));
                if (incompleteCoverage || retainedListing) {
                    Assessments.RemoveAll(assessment => assessment.Code == DnsblCodes.NotListed &&
                        string.Equals(assessment.Target, ipAddressOrHostname, StringComparison.OrdinalIgnoreCase));
                }

                // A shared address may retain several source/family occurrences. Keep
                // identical host/provider listing assessments once while retaining every record.
                var listedAssessments = new HashSet<(string Target, string Source, string Message)>(
                    Assessments.Where(assessment => assessment.Code == DnsblCodes.Listed).Select(assessment =>
                        ((assessment.Target ?? string.Empty).ToUpperInvariant(), (assessment.Source ?? string.Empty).ToUpperInvariant(), assessment.Message)));
                foreach (var rec in results) {
                    if (!rec.QuerySucceeded) {
                        using var incomplete = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSBL", target: ipAddressOrHostname, source: rec.BlackList) : null;
                        var timedOut = rec.Error?.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0 || rec.Error?.IndexOf("budget", StringComparison.OrdinalIgnoreCase) >= 0;
                        var code = timedOut ? DnsblCodes.ProviderTimeout : DnsblCodes.QueryFailed;
                        var message = $"DNSBL provider {rec.BlackList} was not checked: {rec.Error}";
                        incomplete?.AddWarning(message, code);
                        warnings.Add((code, message));
                    }
                    if (rec.IsBlackListed) {
                        var target = rec.SourceHost ?? rec.IpAddress ?? ipAddressOrHostname;
                        var reason = string.IsNullOrWhiteSpace(rec.ReplyMeaning) ? "Listed" : rec.ReplyMeaning;
                        var message = $"{reason} listed on {rec.BlackList}";
                        if (!listedAssessments.Add((target.ToUpperInvariant(), rec.BlackList.ToUpperInvariant(), message))) { continue; }
                        using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSBL", target: target, source: rec.BlackList) : null;
                        _collector?.AddWarning(message, DnsblCodes.Listed);
                        warnings.Add((DnsblCodes.Listed, message));
                    }
                }

                if (!retainedListing && !incompleteCoverage && queryResult.Total > 0) {
                    using var _collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSBL", target: ipAddressOrHostname) : null;
                    _collector?.AddInfo("Not listed on any DNSBL", DnsblCodes.NotListed);
                }

            }
            // Subscribers may read or convert the analysis. Invoke them after atomic evidence publication.
            foreach (var warning in warnings) { logger?.WriteWarningCode(warning.Code, warning.Message); }
        }

        private void RecordSummary(InternalLogger? logger, string? target = null) {
            lock (SyncRoot) {
                using var collector = logger != null ? AssessmentCollector.ForAnalysis(logger, this, category: "DNSBL", target: target) : null;
                var providers = AllResults.Where(record => record.QuerySucceeded).Select(record => record.BlackList).Distinct(StringComparer.OrdinalIgnoreCase).Count();
                collector?.AddInfo($"Checked {providers} providers across {RecordChecked} hosts; listed {Blacklisted}/{RecordChecked}.", DnsblCodes.Summary);
            }
        }
        private static async Task<List<T>> ToListAsync<T>(IAsyncEnumerable<T> source) {
            var list = new List<T>();
            await foreach (var item in source) {
                list.Add(item);
            }
            return list;
        }

        private static readonly Dictionary<string, (bool IsListed, string Meaning)> _generalReplyCodes = new() {
            ["127.0.0.1"] = (false, "Whitelisted"),
            ["127.0.0.2"] = (true, "Blacklisted"),
            ["127.0.0.3"] = (true, "Blacklisted"),
            ["127.0.0.4"] = (true, "Blacklisted")
        };


        private static (bool IsListed, string Meaning) GetReplyCodeMeaning(string blacklist, string reply) {
            if (string.IsNullOrEmpty(reply)) {
                return (false, string.Empty);
            }

            if (reply.StartsWith("127.255.")) {
                return (false, "Reserved");
            }

            if (_providerReplyCodes.TryGetValue(blacklist, out var providerMap) &&
                providerMap.TryGetValue(reply, out var providerResult)) {
                return providerResult;
            }

            if (_generalReplyCodes.TryGetValue(reply, out var result)) {
                return result;
            }

            return reply.StartsWith("127.") ? (true, "Listed") : (true, string.Empty);
        }

        private static string FormatDnsblName(IPAddress ipAddress) {
            return ipAddress.ToPtrFormat();
        }

        /// <summary>
        /// Adds a DNSBL provider to the internal list if not already present.
        /// </summary>
        /// <param name="dnsbl">Blacklist host name.</param>
        /// <param name="enabled">Whether the entry should be queried.</param>
        /// <param name="comment">Optional descriptive comment.</param>
        /// <param name="port">DNS port used when querying.</param>
        public void AddDNSBL(string dnsbl, bool enabled = true, string? comment = null, int port = 53) {
            if (string.IsNullOrWhiteSpace(dnsbl))
                return;

            dnsbl = dnsbl.ToLowerInvariant();
            var entry = DnsblEntries.FirstOrDefault(e =>
                StringComparer.OrdinalIgnoreCase.Equals(e.Domain, dnsbl));
            if (entry == null) {
                DnsblEntries.Add(new DnsblEntry(dnsbl, enabled, comment, port));
            } else {
                entry.Enabled = enabled;
                entry.Comment = comment;
                entry.Port = port;
            }
        }

        /// <summary>Gets a read only view of configured DNSBL providers.</summary>
        public IReadOnlyList<DnsblEntry> GetDNSBL() {
            return DnsblEntries.AsReadOnly();
        }

        /// <summary>
        /// Adds multiple DNSBL providers.
        /// </summary>
        /// <param name="dnsbls">Collection of DNSBL host names.</param>
        public void AddDNSBL(IEnumerable<string> dnsbls) {
            foreach (var dnsbl in dnsbls) {
                AddDNSBL(dnsbl);
            }
        }

        /// <summary>
        /// Removes a DNSBL provider from the list if it exists.
        /// </summary>
        /// <param name="dnsbl">Blacklist host name.</param>
        public void RemoveDNSBL(string dnsbl) {
            if (string.IsNullOrWhiteSpace(dnsbl))
                return;

            dnsbl = dnsbl.ToLowerInvariant();
            var entry = DnsblEntries.FirstOrDefault(e =>
                string.Equals(e.Domain, dnsbl, StringComparison.OrdinalIgnoreCase));
            if (entry != null) {
                DnsblEntries.Remove(entry);
            }
        }

        /// <summary>Clears all configured DNSBL providers.</summary>
        public void ClearDNSBL() {
            DnsblEntries.Clear();
        }

        /// <summary>
        /// Loads DNSBL entries from a simple text file.
        /// </summary>
        /// <param name="filePath">File containing provider domains.</param>
        /// <param name="clearExisting">When set to <c>true</c> existing entries are removed before loading.</param>
        public void LoadDNSBL(string filePath, bool clearExisting = false) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNSBL list file not found: {filePath}");
            }

            var lines = File.ReadAllLines(filePath, Encoding.UTF8);

            if (clearExisting) {
                ClearDNSBL();
            }

            foreach (var line in lines) {
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed))
                    continue;

                if (trimmed.StartsWith(":%", StringComparison.Ordinal))
                    continue;

                bool enabled = true;
                if (trimmed.StartsWith("#")) {
                    enabled = false;
                    trimmed = trimmed.Substring(1).Trim();
                }

                string? comment = null;
                var commentIndex = trimmed.IndexOf('#');
                if (commentIndex >= 0) {
                    comment = trimmed.Substring(commentIndex + 1).Trim();
                    trimmed = trimmed.Substring(0, commentIndex).Trim();
                }

                trimmed = trimmed.TrimEnd('#').Trim();

                if (!string.IsNullOrWhiteSpace(trimmed)) {
                    AddDNSBL(trimmed, enabled, comment);
                }
            }
        }

        /// <summary>
        /// Loads DNSBL configuration from a JSON file.
        /// </summary>
        /// <param name="filePath">Path to JSON configuration file.</param>
        /// <param name="overwriteExisting">Replace existing entries if they already exist.</param>
        /// <param name="clearExisting">Remove existing entries before loading.</param>
        public void LoadDnsblConfig(string filePath, bool overwriteExisting = false, bool clearExisting = false) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNSBL config file not found: {filePath}");
            }

            var lines = File.ReadAllLines(filePath);
            var json = string.Join("\n", lines);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var config = JsonSerializer.Deserialize<DnsblConfiguration>(json, options);
            if (config != null) {
                ApplyDnsblConfiguration(config, overwriteExisting, clearExisting);
            }
        }

        private void ApplyDnsblConfiguration(DnsblConfiguration config, bool overwriteExisting, bool clearExisting) {
            if (clearExisting) {
                ClearDNSBL();
                lock (_domainListLock) { _domainBlockLists.Clear(); }
                _providerReplyCodes.Clear();
                BlockLists.Entries.Clear();
            }

            if (config.Providers != null) {
                var processed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var provider in config.Providers) {
                    if (!processed.Add(provider.Domain))
                        continue;

                    var existing = DnsblEntries.FirstOrDefault(e => StringComparer.OrdinalIgnoreCase.Equals(e.Domain, provider.Domain));
                    if (existing == null) {
                        var entry = new DnsblEntry(provider.Domain, provider.Enabled, provider.Comment, provider.Port);
                        if (provider.ReplyCodes?.Count > 0)
                            entry.ReplyCodes = new Dictionary<string, DnsblReplyCode>(provider.ReplyCodes, StringComparer.OrdinalIgnoreCase);
                        DnsblEntries.Add(entry);
                    } else if (overwriteExisting) {
                        existing.Enabled = provider.Enabled;
                        existing.Comment = provider.Comment;
                        existing.Port = provider.Port;
                        if (provider.ReplyCodes?.Count > 0)
                            existing.ReplyCodes = new Dictionary<string, DnsblReplyCode>(provider.ReplyCodes, StringComparer.OrdinalIgnoreCase);
                    }

                    if (provider.ReplyCodes?.Count > 0) {
                        if (clearExisting || !_providerReplyCodes.TryGetValue(provider.Domain, out var map)) {
                            map = new Dictionary<string, (bool, string)>(StringComparer.OrdinalIgnoreCase);
                            _providerReplyCodes[provider.Domain] = map;
                        }
                        foreach (var code in provider.ReplyCodes) {
                            if (!map.ContainsKey(code.Key) || overwriteExisting)
                                map[code.Key] = (code.Value.IsListed, code.Value.Meaning);
                        }
                    }
                }
            }

            if (config.DomainBlockLists != null) {
                lock (_domainListLock) {
                    foreach (var entry in config.DomainBlockLists
                        .Where(e => e != null && !string.IsNullOrWhiteSpace(e.Domain))) {
                        var existing = _domainBlockLists.FirstOrDefault(e => StringComparer.OrdinalIgnoreCase.Equals(e.Domain, entry.Domain));
                        if (existing == null) {
                            _domainBlockLists.Add(new DnsblEntry(entry.Domain, entry.Enabled, entry.Comment, entry.Port));
                        } else if (overwriteExisting) {
                            existing.Enabled = entry.Enabled;
                            existing.Comment = entry.Comment;
                            existing.Port = entry.Port;
                        }
                    }
                }
            }

            if (config.IpBlockLists != null) {
                foreach (var entry in config.IpBlockLists) {
                    var existing = BlockLists.Entries.FirstOrDefault(e => string.Equals(e.Name, entry.Name, StringComparison.OrdinalIgnoreCase));
                    if (existing == null) {
                        BlockLists.Entries.Add(new BlockListEntry {
                            Name = entry.Name,
                            Url = entry.Url,
                            Enabled = entry.Enabled,
                            Comment = entry.Comment
                        });
                    } else if (overwriteExisting) {
                        existing.Url = entry.Url;
                        existing.Enabled = entry.Enabled;
                        existing.Comment = entry.Comment;
                    }
                }
            }

        }

        /// <summary>Executes the update dnsbl data async operation.</summary>
        public async Task UpdateDnsblDataAsync(string url = DefaultUpdateUrl, bool overwriteExisting = true) {
            var client = SharedHttpClient.Instance;
            var json = await client.GetStringAsync(url);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var config = JsonSerializer.Deserialize<DnsblConfiguration>(json, options);
            if (config != null) {
                ApplyDnsblConfiguration(config, overwriteExisting, overwriteExisting);
            }
        }
    }
}
