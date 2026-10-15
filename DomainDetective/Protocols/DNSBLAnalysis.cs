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
        public Dictionary<string, DNSQueryResult> Results { get; set; } = new Dictionary<string, DNSQueryResult>();

        /// <summary>Gets a flattened list of all DNSBL records returned.</summary>
        public List<DNSBLRecord> AllResults { get; private set; } = new List<DNSBLRecord>();

        internal InternalLogger? Logger { get; set; } = new InternalLogger();
        /// <summary>Gets the assessments value.</summary>
        public List<Assessment> Assessments { get; } = new();

        /// <summary>
        /// Clears cached results allowing the instance to be reused.
        /// </summary>
        public void Reset() {
            lock (SyncRoot) {
                Results = new Dictionary<string, DNSQueryResult>();
                AllResults = new List<DNSBLRecord>();
                Logger = null;
                Subject = null;
                Assessments.Clear();
                DiscoverySucceeded = true;
                DiscoveryErrors.Clear();
                _failedDiscoverySources.Clear();

            }
        }

        internal async Task AnalyzeDNSBLRecordsMX(string domainName, InternalLogger logger, bool clearExisting = true, DomainIpScanMode scanMode = DomainIpScanMode.MxThenApexFallback, System.Threading.CancellationToken cancellationToken = default, QueryRun? queryRun = null) {
            if (clearExisting) {
                Reset();
            }
            Logger = logger;
            Subject = domainName;
            var run = queryRun ?? BeginQueryRun(cancellationToken);

            var mxRecords = scanMode == DomainIpScanMode.ApexOnly || scanMode == DomainIpScanMode.ApexAOnly || scanMode == DomainIpScanMode.ApexAAAAOnly
                ? Array.Empty<DnsAnswer>() : await QueryDiscoveryAsync(run, domainName, DnsRecordType.MX,
                    scanMode == DomainIpScanMode.MxAOnly ? new[] { DnsblIpSource.MxA } :
                    scanMode == DomainIpScanMode.MxAAAAOnly ? new[] { DnsblIpSource.MxAAAA } :
                    new[] { DnsblIpSource.MxA, DnsblIpSource.MxAAAA });

            Logger?.WriteVerbose($"Checking {domainName} against {DomainDNSBLLists.Count} domain blacklists");
            var resultsDomain = await ToListAsync(QueryDNSBL(DomainDNSBLLists, domainName, run, DnsblIpSource.Domain, sourceHost: domainName));
            ConvertToResults(domainName, resultsDomain);

            bool anyIpChecked = false;

            // Helper local function to query and convert results for a set of IPs in parallel
            async Task QueryIpsAsync(IEnumerable<(string ip, string host)> items, DnsblIpSource source, string sourceLabel) {
                var pairs = items?.ToList() ?? new List<(string ip, string host)>();
                if (pairs.Count == 0) return;
                Logger?.WriteVerbose($"Checking {pairs.Count} {sourceLabel} input(s) against {DNSBLLists.Count} blacklists (parallel)…");
                var results = await Helpers.BoundedAsync.RunAsync(pairs, async pair => {
                    var key = pair.ip; var h = pair.host;
                        var list = new List<DNSBLRecord>();
                        await foreach (var rec in QueryDNSBL(DNSBLLists, key, run, source, sourceHost: h)) list.Add(rec);
                        return (key, list);
                }, 16, run.CallerToken);
                foreach (var (key, records) in results) {
                    ConvertToResults(key, records);
                    anyIpChecked = true;
                }
            }

            // Parse MX hostnames and resolve as needed
            List<string> ParseMxHosts() {
                var hosts = new List<string>();
                foreach (var mx in mxRecords) {
                    var data = (mx.Data ?? string.Empty).Trim();
                    if (string.IsNullOrEmpty(data)) continue;
                    var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length == 0) continue;
                    for (int i = 0; i < parts.Length; i++) parts[i] = parts[i].Trim();
                    var host = parts.Length >= 2 ? parts[1] : parts[0];
                    if (host.EndsWith(".", StringComparison.Ordinal)) host = host.Substring(0, host.Length - 1);
                    if (!string.IsNullOrWhiteSpace(host)) hosts.Add(host);
                }
                return hosts.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            }

            async Task<List<(string ip, string host)>> ResolveMxAsync(DnsRecordType type) {
                var pairs = new List<(string ip, string host)>();
                var hosts = ParseMxHosts();
                if (hosts.Count == 0) return pairs;
                Logger?.WriteVerbose($"Found {hosts.Count} MX host(s): {string.Join(", ", hosts)}");
                foreach (var host in hosts) {
                    var answers = await QueryDiscoveryAsync(run, host, type, type == DnsRecordType.A ? DnsblIpSource.MxA : DnsblIpSource.MxAAAA);
                    pairs.AddRange(answers.Select(a => (a.Data, host)));
                }
                return pairs;
            }

            // Resolve apex (A/AAAA) as needed
            async Task<List<(string ip, string host)>> ResolveApexAsync(DnsRecordType type) {
                var answers = await QueryDiscoveryAsync(run, domainName, type, type == DnsRecordType.A ? DnsblIpSource.ApexA : DnsblIpSource.ApexAAAA);
                return answers.Select(a => (a.Data, domainName)).ToList();
            }

            switch (scanMode) {
                case DomainIpScanMode.MxOnly:
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.A), DnsblIpSource.MxA, "MX A");
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.AAAA), DnsblIpSource.MxAAAA, "MX AAAA");
                    break;
                case DomainIpScanMode.MxAOnly:
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.A), DnsblIpSource.MxA, "MX A");
                    break;
                case DomainIpScanMode.MxAAAAOnly:
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.AAAA), DnsblIpSource.MxAAAA, "MX AAAA");
                    break;
                case DomainIpScanMode.ApexOnly:
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.A), DnsblIpSource.ApexA, "A apex");
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.AAAA), DnsblIpSource.ApexAAAA, "AAAA apex");
                    break;
                case DomainIpScanMode.ApexAOnly:
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.A), DnsblIpSource.ApexA, "A apex");
                    break;
                case DomainIpScanMode.ApexAAAAOnly:
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.AAAA), DnsblIpSource.ApexAAAA, "AAAA apex");
                    break;
                case DomainIpScanMode.MxAndApex:
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.A), DnsblIpSource.MxA, "MX A");
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.AAAA), DnsblIpSource.MxAAAA, "MX AAAA");
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.A), DnsblIpSource.ApexA, "A apex");
                    await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.AAAA), DnsblIpSource.ApexAAAA, "AAAA apex");
                    break;
                case DomainIpScanMode.MxThenApexFallback:
                default:
                    Logger?.WriteVerbose($"Checking {domainName} MX records against {DNSBLLists.Count} blacklists");
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.A), DnsblIpSource.MxA, "MX A");
                    await QueryIpsAsync(await ResolveMxAsync(DnsRecordType.AAAA), DnsblIpSource.MxAAAA, "MX AAAA");
                    if (!anyIpChecked) {
                        Logger?.WriteVerbose($"No IPs resolved from MX hosts; falling back to apex A/AAAA.");
                        await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.A), DnsblIpSource.ApexA, "A apex");
                        await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.AAAA), DnsblIpSource.ApexAAAA, "AAAA apex");
                    }
                    break;
            }

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
            var run = BeginQueryRun(default);
            Logger = logger;
            Logger?.WriteVerbose($"Checking {ipAddressOrHostname} against {DNSBLLists.Count} blacklists");
            var collected = new List<DNSBLRecord>();
            var isIp = System.Net.IPAddress.TryParse(ipAddressOrHostname, out _);
            DnsblIpSource? src = isIp ? DnsblIpSource.UserProvided : DnsblIpSource.Domain;
            string srcHost = isIp ? "UserProvided" : ipAddressOrHostname;
            await foreach (var record in QueryDNSBL(DNSBLLists, ipAddressOrHostname, run, src, sourceHost: srcHost)) {
                collected.Add(record);
                yield return record;
            }
            ConvertToResults(ipAddressOrHostname, collected);
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
            Logger = logger;
            if (items.Count == 0) return;
            var run = queryRun ?? BeginQueryRun(cancellationToken);

            Logger?.WriteVerbose($"Checking {items.Count} input(s) against {DNSBLLists.Count} blacklists (parallel)…");

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
                ConvertToResults(key, records);
            }

            cancellationToken.ThrowIfCancellationRequested();
            RecordSummary(logger);
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results) {
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
                bool incompleteCoverage = !DiscoverySucceeded || AllResults.Any(record => !record.QuerySucceeded);
                bool retainedListing = AllResults.Any(record => record.IsBlackListed &&
                    string.Equals(GetRecordTargetKey(record), ipAddressOrHostname, StringComparison.OrdinalIgnoreCase));
                if (incompleteCoverage) {
                    Assessments.RemoveAll(assessment => assessment.Code == DnsblCodes.NotListed);
                } else if (retainedListing) {
                    Assessments.RemoveAll(assessment => assessment.Code == DnsblCodes.NotListed &&
                        string.Equals(assessment.Target, ipAddressOrHostname, StringComparison.OrdinalIgnoreCase));
                }

                // Emit assessments for any listed records
                foreach (var rec in results) {
                    if (!rec.QuerySucceeded) {
                        using var incomplete = Logger != null ? AssessmentCollector.ForAnalysis(Logger, this, category: "DNSBL", target: ipAddressOrHostname, source: rec.BlackList) : null;
                        var timedOut = rec.Error?.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0 || rec.Error?.IndexOf("budget", StringComparison.OrdinalIgnoreCase) >= 0;
                        Logger?.WriteWarningCode(timedOut ? DnsblCodes.ProviderTimeout : DnsblCodes.QueryFailed, "DNSBL provider {0} was not checked: {1}", rec.BlackList, rec.Error);
                    }
                    if (rec.IsBlackListed) {
                        using var _collector = Logger != null ? AssessmentCollector.ForAnalysis(Logger, this, category: "DNSBL", target: rec.SourceHost ?? rec.IpAddress ?? ipAddressOrHostname, source: rec.BlackList) : null;
                        var reason = string.IsNullOrWhiteSpace(rec.ReplyMeaning) ? "Listed" : rec.ReplyMeaning;
                        Logger?.WriteWarningCode(DnsblCodes.Listed, "{0} listed on {1}", reason, rec.BlackList);
                    }
                }

                if (!retainedListing && !incompleteCoverage && queryResult.Total > 0) {
                    using var _collector = Logger != null ? AssessmentCollector.ForAnalysis(Logger, this, category: "DNSBL", target: ipAddressOrHostname) : null;
                    _collector?.AddInfo("Not listed on any DNSBL", DnsblCodes.NotListed);
                }

            }
        }

        private void RecordSummary(InternalLogger? logger, string? target = null) {
            lock (SyncRoot) {
                if (!DiscoverySucceeded) { Assessments.RemoveAll(assessment => assessment.Code == DnsblCodes.NotListed); }
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
