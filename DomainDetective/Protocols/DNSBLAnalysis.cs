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
    /// Represents the outcome of a single DNSBL query entry.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DNSBLRecord {
        /// <summary>Plain IPv4/IPv6 for IP-based checks; null for domain-based checks.</summary>
        public string IpAddress { get; set; }
        /// <summary>Indicates where the IP address originated from (for IP-based checks).</summary>
        public DnsblIpSource? IpSource { get; set; }
        /// <summary>Optional host label that produced the IP (e.g., apex domain or MX host).</summary>
        public string SourceHost { get; set; }
        /// <summary>Indicates whether this record came from a domain or IP-based query.</summary>
        public DnsblQueryKind QueryKind { get; set; }
        /// <summary>Gets or sets the blacklist domain.</summary>
        public string BlackList { get; set; }
        //public string BlackListReason { get; set; }
        /// <summary>Gets or sets a value indicating whether the address was listed.</summary>
        public bool IsBlackListed { get; set; }
        /// <summary>Gets or sets the raw DNSBL response.</summary>
        public string Answer { get; set; }
        /// <summary>Gets or sets the interpreted meaning of <see cref="Answer"/>.</summary>
        public string ReplyMeaning { get; set; }
        //public string NameServer { get; set; }
        /// <summary>Gets or sets the fully qualified domain name that was queried.</summary>
        public string FQDN { get; set; }
        /// <summary>DNSBL base query label (e.g., reversed IP or domain without provider).
        /// For provider-specific full query, see <see cref="FQDN"/>.</summary>
        public string Query { get; set; }
    }

    /// <summary>
    /// Aggregates multiple DNSBL query outcomes for a host.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DNSQueryResult {
        /// <summary>Gets or sets the host that was checked.</summary>
        public string Host { get; set; }
        /// <summary>Gets or sets the DNSBL results.</summary>
        public IEnumerable<DNSBLRecord> DNSBLRecords { get; set; }
        /// <summary>Gets the number of blacklists that reported a listing.</summary>
        public int Listed => DNSBLRecords.Count(record => record.IsBlackListed);

        /// <summary>Gets the names of blacklists that reported a listing.</summary>
        public List<string> ListedBlacklist => DNSBLRecords.Where(record => record.IsBlackListed).Select(record => record.BlackList).ToList();

        /// <summary>Gets the number of lists where the host was not found.</summary>
        public int NotListed => DNSBLRecords.Count(record => !record.IsBlackListed);
        /// <summary>Gets the total number of DNSBL checks performed.</summary>
        public int Total => DNSBLRecords.Count();
        /// <summary>Gets a value indicating whether the host was listed on any blacklist.</summary>
        public bool IsBlacklisted => Listed > 0;
    }

    /// <summary>
    /// Represents a DNSBL server configuration entry.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsblEntry {
        /// <summary>Gets or sets the blacklist domain.</summary>
        public string Domain { get; set; }
        /// <summary>Gets or sets a value indicating whether the entry is used during checks.</summary>
        public bool Enabled { get; set; } = true;
        /// <summary>Gets or sets optional descriptive text.</summary>
        public string Comment { get; set; }
        /// <summary>Gets or sets provider specific reply codes.</summary>
        public Dictionary<string, DnsblReplyCode> ReplyCodes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

        /// <summary>Gets or sets the DNS port to use for queries.</summary>
        public int Port { get; set; } = 53;

        public DnsblEntry() { }
        public DnsblEntry(string domain, bool enabled = true, string comment = null, int port = 53) {
            Domain = domain;
            Enabled = enabled;
            Comment = comment;
            Port = port;
        }
    }

    /// <summary>
    /// Provides routines to query DNS block lists for a host.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Both IP- and domain-based blacklists are supported. Results include
    /// detailed reply codes for further interpretation.
    /// </remarks>
    public partial class DNSBLAnalysis {
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
                        if (config.DomainBlockLists != null)
                            _defaultDomainBlockLists.AddRange(config.DomainBlockLists);
                        if (config.IpBlockLists != null)
                            _defaultIpBlockLists.AddRange(config.IpBlockLists);
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
        /// Use <see cref="AddDNSBL(string, bool, string)"/>, <see cref="RemoveDNSBL(string)"/>,
        /// <see cref="ClearDNSBL()"/>, <see cref="LoadDNSBL(string, bool)"/> or
        /// <see cref="LoadDnsblConfig(string, bool, bool)"/> to modify the list.
        /// </summary>
        /// <value>
        /// The DNSBL provider entries.
        /// </value>
        internal List<DnsblEntry> DnsblEntries { get; } = new();

        public DNSBLAnalysis(DnsConfiguration dnsConfiguration = null) {
            DnsConfiguration = dnsConfiguration ?? new DnsConfiguration();
            DnsblEntries.AddRange(_defaultEntries.Select(e => {
                var entry = new DnsblEntry(e.Domain, e.Enabled, e.Comment, e.Port);
                if (e.ReplyCodes?.Count > 0)
                    entry.ReplyCodes = new Dictionary<string, DnsblReplyCode>(e.ReplyCodes, StringComparer.OrdinalIgnoreCase);
                return entry;
            }));
            _domainBlockLists.AddRange(_defaultDomainBlockLists.Select(e => new DnsblEntry(e.Domain, e.Enabled, e.Comment, e.Port)));
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
        public bool IsBlacklisted => Results.Any(r => r.Value.IsBlacklisted);
        /// <summary>Gets the number of hosts or addresses checked.</summary>
        public int RecordChecked => Results.Count;
        /// <summary>Gets the count of hosts that were listed.</summary>
        public int Blacklisted => Results.Count(r => r.Value.IsBlacklisted);
        /// <summary>Gets the count of hosts that were not listed.</summary>
        public int NotBlacklisted => Results.Count(r => !r.Value.IsBlacklisted);

        /// <summary>Gets the per-host DNSBL query results.</summary>
        public Dictionary<string, DNSQueryResult> Results { get; set; } = new Dictionary<string, DNSQueryResult>();

        /// <summary>Gets a flattened list of all DNSBL records returned.</summary>
        public List<DNSBLRecord> AllResults { get; private set; } = new List<DNSBLRecord>();

        internal InternalLogger Logger { get; set; } = new InternalLogger();

        /// <summary>
        /// Clears cached results allowing the instance to be reused.
        /// </summary>
        public void Reset() {
            Results = new Dictionary<string, DNSQueryResult>();
            AllResults = new List<DNSBLRecord>();
            Logger = null;
        }

        private async Task<IEnumerable<DnsResponse>> QueryFullDns(string[] names, DnsRecordType type) {
            if (QueryDnsFullOverride != null) {
                return await QueryDnsFullOverride(names, type);
            }

            return await DnsConfiguration.QueryFullDNS(names, type);
        }

        internal async Task AnalyzeDNSBLRecordsMX(string domainName, InternalLogger logger, bool clearExisting = true, DomainIpScanMode scanMode = DomainIpScanMode.MxThenApexFallback) {
            if (clearExisting) {
                Reset();
            }
            Logger = logger;

            DnsAnswer[] mxRecords;
            try {
                mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX);
            } catch {
                mxRecords = System.Array.Empty<DnsClientX.DnsAnswer>();
            }

            Logger?.WriteVerbose($"Checking {domainName} against {DomainDNSBLLists.Count} domain blacklists");
            var resultsDomain = await ToListAsync(QueryDNSBL(DomainDNSBLLists, domainName, DnsblIpSource.Domain, sourceHost: domainName));
            ConvertToResults(domainName, resultsDomain);

            bool anyIpChecked = false;

            // Helper local function to query and convert results for a set of IPs
            async Task QueryIpsAsync(IEnumerable<(string ip, string host)> items, DnsblIpSource source, string sourceLabel) {
                foreach (var (ip, host) in items) {
                    Logger?.WriteVerbose($"Checking {ip} ({sourceLabel}) against {DNSBLLists.Count} blacklists");
                    var results = await ToListAsync(QueryDNSBL(DNSBLLists, ip, source, sourceHost: host));
                    ConvertToResults(ip, results);
                    anyIpChecked = true;
                }
            }

            // Parse MX hostnames and resolve as needed
            List<string> ParseMxHosts() {
                var hosts = new List<string>();
                foreach (var mx in mxRecords) {
                    var data = (mx.Data ?? string.Empty).Trim();
                    if (string.IsNullOrEmpty(data)) continue;
                    string host = null;
                    var parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    for (int i = 0; i < parts.Length; i++) parts[i] = parts[i].Trim();
                    if (parts.Length >= 2) host = parts[1];
                    else host = parts[0];
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
                    var answers = await DnsConfiguration.QueryDNS(host, type);
                    pairs.AddRange(answers.Select(a => (a.Data, host)));
                }
                return pairs;
            }

            // Resolve apex (A/AAAA) as needed
            async Task<List<(string ip, string host)>> ResolveApexAsync(DnsRecordType type) {
                var answers = await DnsConfiguration.QueryDNS(domainName, type);
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
                        try {
                            await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.A), DnsblIpSource.ApexA, "A apex");
                            await QueryIpsAsync(await ResolveApexAsync(DnsRecordType.AAAA), DnsblIpSource.ApexAAAA, "AAAA apex");
                        } catch { /* ignore apex fallback errors */ }
                    }
                    break;
            }
        }

        /// <summary>
        /// Queries the configured DNSBL providers for the specified host or IP address.
        /// </summary>
        /// <param name="ipAddressOrHostname">Address or hostname to query.</param>
        /// <param name="logger">Logger for verbose output.</param>
        /// <returns>Enumeration of <see cref="DNSBLRecord"/> objects.</returns>
        public async IAsyncEnumerable<DNSBLRecord> AnalyzeDNSBLRecords(string ipAddressOrHostname, InternalLogger logger) {
            Reset();
            Logger = logger;
            Logger?.WriteVerbose($"Checking {ipAddressOrHostname} against {DNSBLLists.Count} blacklists");
            var collected = new List<DNSBLRecord>();
            var isIp = System.Net.IPAddress.TryParse(ipAddressOrHostname, out _);
            DnsblIpSource? src = isIp ? DnsblIpSource.UserProvided : DnsblIpSource.Domain;
            string srcHost = isIp ? "UserProvided" : ipAddressOrHostname;
            await foreach (var record in QueryDNSBL(DNSBLLists, ipAddressOrHostname, src, sourceHost: srcHost)) {
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
        public async Task AnalyzeDNSBLRecordsMany(IEnumerable<string> ipAddressesOrHostnames, InternalLogger logger, bool clearExisting = true) {
            if (ipAddressesOrHostnames == null) return;
            var items = ipAddressesOrHostnames.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (clearExisting) {
                Reset();
            }
            Logger = logger;
            if (items.Count == 0) return;

            Logger?.WriteVerbose($"Checking {items.Count} input(s) against {DNSBLLists.Count} blacklists (parallel)…");

            var tasks = new List<Task<(string key, List<DNSBLRecord> records)>>();
            foreach (var item in items) {
                var name = item; // capture
                tasks.Add(Task.Run(async () => {
                    var list = new List<DNSBLRecord>();
                    var isIpInner = System.Net.IPAddress.TryParse(name, out _);
                    DnsblIpSource? srcInner = isIpInner ? DnsblIpSource.UserProvided : DnsblIpSource.Domain;
                    string srcHostInner = isIpInner ? "UserProvided" : name;
                    await foreach (var record in QueryDNSBL(DNSBLLists, name, srcInner, sourceHost: srcHostInner)) {
                        list.Add(record);
                    }
                    return (name, list);
                }));
            }

            var results = await Task.WhenAll(tasks);
            foreach (var (key, records) in results) {
                ConvertToResults(key, records);
            }
        }

        private void ConvertToResults(string ipAddressOrHostname, IEnumerable<DNSBLRecord> results) {
            DNSQueryResult queryResult = new DNSQueryResult {
                Host = ipAddressOrHostname,
                DNSBLRecords = results,
            };
            if (Results.ContainsKey(ipAddressOrHostname)) {
                Results.Remove(ipAddressOrHostname);
            }
            Results[ipAddressOrHostname] = queryResult;
            AllResults.AddRange(results);
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

        private async IAsyncEnumerable<DNSBLRecord> QueryDNSBL(IEnumerable<string> dnsblList, string ipAddressOrHostname, DnsblIpSource? ipSource = null, string sourceHost = null) {
            // Gracefully handle missing/empty provider lists to avoid crashes when configuration isn't loaded
            if (dnsblList == null)
                yield break;
            if (!dnsblList.Any())
                yield break;

            // Check if the input is an IP address or a hostname
            string name;
            var isIp = IPAddress.TryParse(ipAddressOrHostname, out IPAddress ipAddress);
            if (isIp) {
                name = FormatDnsblName(ipAddress);
            } else {
                name = ipAddressOrHostname;
            }

            List<string> queries = new List<string>();
            foreach (var dnsbl in dnsblList) {
                string query = $"{name}.{dnsbl}";
                Logger?.WriteVerbose($"Querying blacklist domain {dnsbl} with query {query}");
                queries.Add(query);
            }

            if (queries.Count == 0)
                yield break;

            var responses = new Dictionary<string, List<DnsAnswer>>(StringComparer.OrdinalIgnoreCase);

            try {
                var resultA = (await QueryFullDns(queries.ToArray(), DnsRecordType.A)).ToArray();
                for (int i = 0; i < queries.Count; i++) {
                    var answers = i < resultA.Length ? resultA[i].Answers : Array.Empty<DnsAnswer>();
                    responses[queries[i]] = answers?.ToList() ?? new List<DnsAnswer>();
                }
            } catch (Exception ex) when (ex is UriFormatException || ex is InvalidOperationException || ex is System.Net.Sockets.SocketException || ex is System.Threading.Tasks.TaskCanceledException || ex is System.OperationCanceledException || ex is System.TimeoutException) {
                // fallback to empty responses when the system DNS configuration is invalid
                foreach (var query in queries) {
                    responses[query] = new List<DnsAnswer>();
                }
            }

            if (IPAddress.TryParse(ipAddressOrHostname, out IPAddress ip) && ip.AddressFamily == AddressFamily.InterNetworkV6) {
                try {
                    var resultAaaa = (await QueryFullDns(queries.ToArray(), DnsRecordType.AAAA)).ToArray();
                    for (int i = 0; i < queries.Count; i++) {
                        var answers = i < resultAaaa.Length ? resultAaaa[i].Answers : Array.Empty<DnsAnswer>();
                        if (!responses.ContainsKey(queries[i])) {
                            responses[queries[i]] = answers?.ToList() ?? new List<DnsAnswer>();
                        } else {
                            responses[queries[i]].AddRange(answers ?? Array.Empty<DnsAnswer>());
                        }
                    }
                } catch (Exception ex) when (ex is UriFormatException || ex is InvalidOperationException || ex is System.Net.Sockets.SocketException || ex is System.Threading.Tasks.TaskCanceledException || ex is System.OperationCanceledException || ex is System.TimeoutException) {
                    foreach (var query in queries) {
                        if (!responses.ContainsKey(query)) {
                            responses[query] = new List<DnsAnswer>();
                        }
                    }
                }
            }

            foreach (var pair in responses) {
                if (pair.Value.Count == 0) {
                    var blacklist = pair.Key.Length > name.Length + 1
                        ? pair.Key.Substring(name.Length + 1)
                        : string.Empty;
                    var dnsblRecord = new DNSBLRecord {
                        Query = name,
                        IpAddress = isIp ? ipAddressOrHostname : null,
                        IpSource = ipSource,
                        SourceHost = sourceHost,
                        QueryKind = isIp ? (ipAddress.AddressFamily == AddressFamily.InterNetwork ? DnsblQueryKind.IpAddressV4 : DnsblQueryKind.IpAddressV6) : DnsblQueryKind.Domain,
                        FQDN = pair.Key,
                        BlackList = blacklist,
                        IsBlackListed = false,
                        Answer = string.Empty,
                        ReplyMeaning = string.Empty,
                    };
                    yield return dnsblRecord;
                } else {
                    foreach (var record in pair.Value) {
                        var blacklist = record.Name.Length > name.Length + 1
                            ? record.Name.Substring(name.Length + 1)
                            : string.Empty;
                        var dnsblRecord = new DNSBLRecord {
                            Query = name,
                            IpAddress = isIp ? ipAddressOrHostname : null,
                            IpSource = ipSource,
                            SourceHost = sourceHost,
                            QueryKind = isIp ? (ipAddress.AddressFamily == AddressFamily.InterNetwork ? DnsblQueryKind.IpAddressV4 : DnsblQueryKind.IpAddressV6) : DnsblQueryKind.Domain,
                            FQDN = record.Name,
                            BlackList = blacklist,
                            IsBlackListed = true,
                            Answer = record.Data,
                        };

                        var info = GetReplyCodeMeaning(dnsblRecord.BlackList, dnsblRecord.Answer);
                        dnsblRecord.IsBlackListed = info.IsListed;
                        dnsblRecord.ReplyMeaning = info.Meaning;

                        yield return dnsblRecord;
                    }
                }
            }
        }

        /// <summary>
        /// Adds a DNSBL provider to the internal list if not already present.
        /// </summary>
        /// <param name="dnsbl">Blacklist host name.</param>
        /// <param name="enabled">Whether the entry should be queried.</param>
        /// <param name="comment">Optional descriptive comment.</param>
        /// <param name="port">DNS port used when querying.</param>
        public void AddDNSBL(string dnsbl, bool enabled = true, string comment = null, int port = 53) {
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

                string comment = null;
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
                _domainBlockLists.Clear();
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
                foreach (var entry in config.DomainBlockLists) {
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
