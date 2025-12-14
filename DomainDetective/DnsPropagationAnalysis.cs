using DnsClientX;
using DomainDetective.Helpers;
using DomainDetective.Monitoring;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {

    /// <summary>
    /// Provides DNS propagation checks across many public servers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// The analysis compares DNS answers from multiple resolvers to detect
    /// discrepancies during record updates.
    /// </remarks>
    public class DnsPropagationAnalysis {
        private readonly List<PublicDnsEntry> _servers = new();
        private readonly object _serversLock = new();
        private readonly DnsSnapshotManager _snapshotManager = new();
        /// <summary>
        /// Thread-safe random number generator used for selecting a subset of servers.
        /// </summary>
        /// <remarks>
        /// <para>Implemented using <see cref="ThreadLocal{T}"/> to provide a separate
        /// <see cref="Random"/> instance per thread.</para>
        /// </remarks>
        private static readonly ThreadLocal<Random> _rnd = new(() => new Random(Guid.NewGuid().GetHashCode()));

        /// <summary>
        /// Gets the collection of configured DNS servers.
        /// </summary>
        public IReadOnlyList<PublicDnsEntry> Servers {
            get {
                lock (_serversLock) {
                    return _servers.ToList();
                }
            }
        }

        /// <summary>Override DNS queries for testing.</summary>
        internal Func<string, DnsRecordType, PublicDnsEntry, CancellationToken, Task<IEnumerable<string>>>? DnsQueryOverride { get; set; }

        /// <summary>Override geolocation lookup for testing.</summary>
        internal Func<string, CancellationToken, Task<GeoLocationInfo?>>? GeoLookupOverride { get; set; }

        /// <summary>Override BGP lookup for testing.</summary>
        internal Func<string, CancellationToken, Task<int?>>? BgpLookupOverride { get; set; }

        /// <summary>GeoIP database used for lookups.</summary>
        public GeoIpAnalysis GeoIp { get; } = new GeoIpAnalysis();

        /// <summary>Initializes a new instance of the class.</summary>
        public DnsPropagationAnalysis() {
            GeoIp.LoadBuiltinDatabase();
        }

        /// <summary>
        /// Loads DNS server definitions from a JSON file.
        /// </summary>
        /// <param name="filePath">Path to the JSON file.</param>
        /// <param name="clearExisting">Whether to clear any existing servers before loading.</param>
        public void LoadServers(string filePath, bool clearExisting = false) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                throw new ArgumentException("File path cannot be null or whitespace.", nameof(filePath));
            }
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNS server list file not found: {filePath}");
            }

            if (clearExisting) {
                lock (_serversLock) {
                    _servers.Clear();
                }
            }

            using var stream = File.OpenRead(filePath);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            options.Converters.Add(new IPAddressJsonConverter());
            options.Converters.Add(new CountryIdJsonConverter());
            options.Converters.Add(new LocationIdJsonConverter());
            var servers = JsonSerializer.DeserializeAsync<List<PublicDnsEntry>>(stream, options)
                .GetAwaiter().GetResult();
            if (servers == null) {
                throw new InvalidDataException("DNS server list is empty or invalid.");
            }

            foreach (var entry in servers) {
                var ip = NormalizeIpAddress(entry.IPAddress);
                var canonical = GetCanonicalIp(ip);
                if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase) && !entry.IPAddress.IsIPv4MappedToIPv6) {
                    throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
                }

                var trimmed = new PublicDnsEntry {
                    Country = entry.Country,
                    IPAddress = ip,
                    HostName = entry.HostName?.Trim() ?? string.Empty,
                    Location = entry.Location,
                    ASN = entry.ASN,
                    ASNName = entry.ASNName?.Trim() ?? string.Empty,
                    Enabled = entry.Enabled
                };

                lock (_serversLock) {
                    if (_servers.All(s => !s.IPAddress.Equals(trimmed.IPAddress))) {
                        _servers.Add(trimmed);
                    }
                }
            }
        }

        /// <summary>
        /// Loads DNS servers from the embedded resource.
        /// </summary>
        /// <param name="clearExisting">Whether to clear existing entries.</param>
        public void LoadBuiltinServers(bool clearExisting = true) {
            if (clearExisting) {
                lock (_serversLock) {
                    _servers.Clear();
                }
            }

            using var stream = typeof(DnsPropagationAnalysis).Assembly.GetManifestResourceStream("DomainDetective.DNS.PublicDNS.json");
            if (stream == null) {
                return;
            }

            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            options.Converters.Add(new IPAddressJsonConverter());
            options.Converters.Add(new CountryIdJsonConverter());
            options.Converters.Add(new LocationIdJsonConverter());
            var servers = JsonSerializer.Deserialize<List<PublicDnsEntry>>(json, options);
            if (servers == null) {
                return;
            }

            foreach (var entry in servers) {
                var ip = NormalizeIpAddress(entry.IPAddress);
                var canonical = GetCanonicalIp(ip);
                if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase) && !entry.IPAddress.IsIPv4MappedToIPv6) {
                    throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
                }

                var trimmed = new PublicDnsEntry {
                    Country = entry.Country,
                    IPAddress = ip,
                  HostName = entry.HostName?.Trim() ?? string.Empty,
                  Location = entry.Location,
                  ASN = entry.ASN,
                  ASNName = entry.ASNName?.Trim() ?? string.Empty,
                    Enabled = entry.Enabled
                };

                lock (_serversLock) {
                    if (_servers.All(s => !s.IPAddress.Equals(trimmed.IPAddress))) {
                        _servers.Add(trimmed);
                    }
                }
            }
        }

        /// <summary>
        /// Adds the specified DNS server to the list of known servers if it is
        /// not already present.
        /// </summary>
        /// <param name="entry">The server entry to add.</param>
        public void AddServer(PublicDnsEntry entry) {
            if (entry == null || entry.IPAddress == null) {
                return;
            }

            var ip = NormalizeIpAddress(entry.IPAddress);
            var canonical = GetCanonicalIp(ip);
            if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase) && !entry.IPAddress.IsIPv4MappedToIPv6) {
                throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
            }

            lock (_serversLock) {
                if (_servers.All(s => !s.IPAddress.Equals(ip))) {
                    var trimmed = new PublicDnsEntry {
                        Country = entry.Country,
                        IPAddress = ip,
                        HostName = entry.HostName,
                        Location = entry.Location,
                        ASN = entry.ASN,
                        ASNName = entry.ASNName,
                        Enabled = entry.Enabled
                    };
                    _servers.Add(trimmed);
                }
            }
        }

        /// <summary>
        /// Removes a DNS server from the list using its IP address.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void RemoveServer(string ipAddress) {
            if (!TryParseNormalized(ipAddress, out var parsed)) {
                return;
            }
            lock (_serversLock) {
                var existing = _servers.FirstOrDefault(s => s.IPAddress.Equals(parsed));
                if (existing != null) {
                    _servers.Remove(existing);
                }
            }
        }

        /// <summary>
        /// Disables a server so it is not used in queries.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void DisableServer(string ipAddress) {
            if (!TryParseNormalized(ipAddress, out var parsed)) {
                return;
            }
            lock (_serversLock) {
                var existing = _servers.FirstOrDefault(s => s.IPAddress.Equals(parsed));
                if (existing != null && existing.Enabled) {
                    var index = _servers.IndexOf(existing);
                    _servers[index] = new PublicDnsEntry {
                        Country = existing.Country,
                        IPAddress = existing.IPAddress,
                        HostName = existing.HostName,
                        Location = existing.Location,
                        ASN = existing.ASN,
                        ASNName = existing.ASNName,
                        Enabled = false
                    };
                }
            }
        }

        /// <summary>
        /// Enables a previously disabled server.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void EnableServer(string ipAddress) {
            if (!TryParseNormalized(ipAddress, out var parsed)) {
                return;
            }
            lock (_serversLock) {
                var existing = _servers.FirstOrDefault(s => s.IPAddress.Equals(parsed));
                if (existing != null && !existing.Enabled) {
                    var index = _servers.IndexOf(existing);
                    _servers[index] = new PublicDnsEntry {
                        Country = existing.Country,
                        IPAddress = existing.IPAddress,
                        HostName = existing.HostName,
                        Location = existing.Location,
                        ASN = existing.ASN,
                        ASNName = existing.ASNName,
                        Enabled = true
                    };
                }
            }
        }

        /// <summary>
        /// Filters the configured servers optionally by country or location.
        /// </summary>
        /// <param name="country">Country filter.</param>
        /// <param name="location">Location filter.</param>
        /// <param name="take">If specified, randomly selects this many servers.</param>
        /// <returns>The filtered server list.</returns>
        public IEnumerable<PublicDnsEntry> FilterServers(CountryId? country = null, LocationId? location = null, int? take = null) {
            List<PublicDnsEntry> snapshot;
            lock (_serversLock) {
                snapshot = _servers.Where(s => s.Enabled).ToList();
            }

            IEnumerable<PublicDnsEntry> query = snapshot;
            if (country.HasValue) {
                query = query.Where(s => s.Country == country.Value);
            }
            if (location.HasValue) {
                query = query.Where(s => s.Location == location.Value);
            }
            if (take.HasValue) {
                var random = _rnd.Value;
                if (random == null)
                {
                    random = new Random(Guid.NewGuid().GetHashCode());
                    _rnd.Value = random;
                }
                query = query.OrderBy(_ => random.Next()).Take(take.Value);
            }
            return query.ToList();
        }

        /// <summary>
        /// Filters servers using a <see cref="DnsServerQuery"/> builder.
        /// </summary>
        /// <param name="query">Query builder specifying filters.</param>
        /// <returns>The filtered server list.</returns>
        public IEnumerable<PublicDnsEntry> FilterServers(DnsServerQuery? query) {
            if (query == null) {
                return FilterServers();
            }

            return FilterServers(query.Country, query.Location, query.TakeCount);
        }

        /// <summary>
        /// Selects a combined list of servers from multiple countries.
        /// </summary>
        /// <param name="countryCounts">Dictionary mapping country code or name to the number of servers to take.</param>
        /// <returns>List of selected servers.</returns>
        /// <example>
        ///   <summary>Select two servers from Poland and one from Germany.</summary>
        ///   <code>
        /// var servers = analysis.SelectServers(new Dictionary&lt;string, int&gt; { ["PL"] = 2, ["DE"] = 1 });
        /// </code>
        /// </example>
        public List<PublicDnsEntry> SelectServers(Dictionary<string, int> countryCounts) {
            var result = new List<PublicDnsEntry>();
            if (countryCounts == null || countryCounts.Count == 0) {
                return result;
            }

            var added = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in countryCounts) {
                if (kvp.Value <= 0) {
                    continue;
                }

                CountryId id;
                if (!CountryIdExtensions.TryParse(kvp.Key, out id)) {
                    try {
                        var region = new System.Globalization.RegionInfo(kvp.Key);
                        var name = region.EnglishName;
                        if (!CountryIdExtensions.TryParse(name, out id)) {
                            continue;
                        }
                    } catch (ArgumentException) {
                        continue;
                    }
                }

                var servers = FilterServers(id, null, kvp.Value);
                foreach (var server in servers) {
                    if (added.Add(server.IPAddress.ToString())) {
                        result.Add(server);
                    }
                }
            }

            return result;
        }

        private static IPAddress NormalizeIpAddress(IPAddress ipAddress) =>
            ipAddress.IsIPv4MappedToIPv6 ? ipAddress.MapToIPv4() : ipAddress;

        private static bool TryParseNormalized(string value, out IPAddress result) {
            IPAddress? parsed;
            if (!IPAddress.TryParse(value, out parsed) || parsed == null) {
                result = IPAddress.None;
                return false;
            }

            result = NormalizeIpAddress(parsed);
            return true;
        }

        private static string GetCanonicalIp(IPAddress ipAddress) {
            var normalized = NormalizeIpAddress(ipAddress);
            return normalized.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? IPAddress.Parse(normalized.ToString()).ToString()
                : normalized.ToString();
        }

        internal Task<GeoLocationInfo?> GetGeoLocationAsync(string ip, CancellationToken ct) {
            if (GeoLookupOverride != null) {
                return GeoLookupOverride(ip, ct);
            }

            return Task.FromResult(GeoIp.Lookup(ip));
        }

        internal async Task<int?> LookupAsnAsync(string ip, CancellationToken ct) {
            if (BgpLookupOverride != null) {
                return await BgpLookupOverride(ip, ct).ConfigureAwait(false);
            }

            var url = $"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            using var response = await SharedHttpClient.Instance.SendAsync(request, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) {
                return null;
            }
#if NET6_0_OR_GREATER
            using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
#else
            using var stream = await response.Content.ReadAsStreamAsync().WaitWithCancellation(ct).ConfigureAwait(false);
#endif
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
            if (!doc.RootElement.TryGetProperty("data", out var data) || !data.TryGetProperty("asns", out var asns)) {
                return null;
            }
            if (asns.GetArrayLength() == 0) {
                return null;
            }
            return asns[0].GetProperty("asn").GetInt32();
        }

        public async Task ValidateServerAsnsAsync(InternalLogger? logger = null, CancellationToken ct = default) {
            List<PublicDnsEntry> snapshot;
            lock (_serversLock) {
                snapshot = _servers.ToList();
            }

            foreach (var server in snapshot) {
                ct.ThrowIfCancellationRequested();
                if (string.IsNullOrWhiteSpace(server.ASN)) {
                    continue;
                }

                var asn = await LookupAsnAsync(server.IPAddress.ToString(), ct).ConfigureAwait(false);
                if (asn.HasValue && !string.Equals(server.ASN, asn.Value.ToString(), StringComparison.OrdinalIgnoreCase)) {
                    logger?.WriteWarningCode(DnsPropagationCodes.AsnMismatch, "Server {0} expected ASN {1} but is announced by AS{2}", server.IPAddress, server.ASN, asn.Value);
                }
            }
        }

        /// <summary>
        /// Asynchronously queries each provided server for the specified domain
        /// and record type.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="recordType">DNS record type.</param>
        /// <param name="servers">Servers to query.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <param name="progress">Optional progress reporter (0..100).</param>
        /// <param name="maxParallelism">Maximum concurrent queries (0 uses number of servers).</param>
        /// <param name="includeGeo">When true, performs GeoIP lookups for returned IPs.</param>
        /// <returns>A list of query results.</returns>
        public async Task<List<DnsPropagationResult>> QueryAsync(
            string domain,
            DnsRecordType recordType,
            IEnumerable<PublicDnsEntry> servers,
            CancellationToken cancellationToken = default,
            IProgress<double>? progress = null,
            int maxParallelism = 0,
            bool includeGeo = false) {
            var serverList = servers?.ToList() ?? new List<PublicDnsEntry>();
            if (serverList.Count == 0) {
                progress?.Report(100);
                return new List<DnsPropagationResult>();
            }
            maxParallelism = maxParallelism <= 0 ? serverList.Count : Math.Min(maxParallelism, serverList.Count);

            using var semaphore = new SemaphoreSlim(maxParallelism);
            var tasks = serverList
                .Select(async server => {
                    try {
                        await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                    } catch (TaskCanceledException) {
                        throw new OperationCanceledException(cancellationToken);
                    }
                    try {
                        return await QueryServerAsync(domain, recordType, server, includeGeo, cancellationToken).ConfigureAwait(false);
                    } finally {
                        semaphore.Release();
                    }
                })
                .ToList();
            var results = new List<DnsPropagationResult>(serverList.Count);
            var completed = 0;
            while (tasks.Count > 0) {
                var task = await Task.WhenAny(tasks);
                tasks.Remove(task);
                results.Add(await task);
                completed++;
                progress?.Report(completed * 100d / serverList.Count);
            }
            return results;
        }

        private async Task<DnsPropagationResult> QueryServerAsync(string domain, DnsRecordType recordType, PublicDnsEntry server, bool includeGeo, CancellationToken cancellationToken) {
            var sw = Stopwatch.StartNew();
            try {
                IEnumerable<string> records;
                if (DnsQueryOverride != null) {
                    records = await DnsQueryOverride(domain, recordType, server, cancellationToken).ConfigureAwait(false);
                } else {
                    using var client = new ClientX(server.IPAddress.ToString(), DnsRequestFormat.DnsOverUDP, 53);
                    client.EndpointConfiguration.UserAgent = DnsConfiguration.DefaultUserAgent;
                    cancellationToken.ThrowIfCancellationRequested();
                    var response = await client.Resolve(domain, recordType);
                    records = response.Answers.Select(a => a.Data);
                }
                sw.Stop();

                Dictionary<string, GeoLocationInfo>? geo = null;
                if (includeGeo) {
                    geo = new();
                    foreach (var rec in records) {
                        if (IPAddress.TryParse(rec, out var ip)) {
                            var ipStr = GetCanonicalIp(ip);
                            var info = await GetGeoLocationAsync(ipStr, cancellationToken).ConfigureAwait(false);
                            if (info != null) {
                                geo[ipStr] = info;
                            }
                        }
                    }
                }

                return new DnsPropagationResult {
                    Server = server,
                    RecordType = recordType,
                    Duration = sw.Elapsed,
                    Records = records,
                    Success = records.Any(),
                    Geo = geo
                };
            } catch (TaskCanceledException) {
                sw.Stop();
                throw new OperationCanceledException(cancellationToken);
            } catch (OperationCanceledException) {
                sw.Stop();
                throw;
            } catch (Exception ex) {
                sw.Stop();
                return new DnsPropagationResult {
                    Server = server,
                    RecordType = recordType,
                    Duration = sw.Elapsed,
                    Error = ex.Message,
                    Success = false,
                    Records = Array.Empty<string>(),
                    Geo = null
                };
            }
        }

        /// <summary>
        /// Compares results from multiple servers and groups them by the set of
        /// records returned.
        /// </summary>
        /// <param name="results">The results to compare.</param>
        /// <returns>
        /// A dictionary keyed by the record returned and listing the servers along with
        /// their country and location.
        /// </returns>
        public static Dictionary<string, List<DnsComparisonEntry>> CompareResults(IEnumerable<DnsPropagationResult> results) {
            var comparison = new Dictionary<string, List<DnsComparisonEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (var res in results.Where(r => r.Success && r.Records != null)) {
                var normalizedRecords = res.Records
                    .Select(r =>
                        IPAddress.TryParse(r, out var ip)
                            ? GetCanonicalIp(NormalizeIpAddress(ip)).ToLowerInvariant()
                            : r.ToLowerInvariant())
                    .OrderBy(r => r);
                var key = string.Join(",", normalizedRecords);
                if (!comparison.TryGetValue(key, out var list)) {
                    list = new List<DnsComparisonEntry>();
                    comparison[key] = list;
                }
                list.Add(new DnsComparisonEntry {
                    IPAddress = res.Server.IPAddress.ToString(),
                    Country = res.Server.Country,
                    Location = res.Server.Location
                });
            }
            return comparison;
        }

        /// <summary>
        /// Flattens comparison results into <see cref="DnsComparisonDetail"/> objects.
        /// </summary>
        /// <param name="results">The results to analyze.</param>
        /// <returns>List of details for each server and record set.</returns>
        public static List<DnsComparisonDetail> GetComparisonDetails(IEnumerable<DnsPropagationResult> results) {
            var groups = CompareResults(results);
            var details = new List<DnsComparisonDetail>();
            foreach (var kvp in groups) {
                foreach (var entry in kvp.Value) {
                    details.Add(new DnsComparisonDetail {
                        Records = kvp.Key,
                        IPAddress = entry.IPAddress,
                        Country = entry.Country,
                        Location = entry.Location
                    });
                }
            }
            return details;
        }

        /// <summary>Directory used to store snapshot files.</summary>
        public string? SnapshotDirectory {
            get => _snapshotManager.DirectoryPath;
            set => _snapshotManager.DirectoryPath = value;
        }

        /// <summary>
        /// Saves the provided results to a timestamped snapshot file.
        /// </summary>
        /// <param name="domain">Queried domain name.</param>
        /// <param name="recordType">DNS record type.</param>
        /// <param name="results">Results to persist.</param>
        public void SaveSnapshot(string domain, DnsRecordType recordType, IEnumerable<DnsPropagationResult> results) {
            _snapshotManager.SaveSnapshot(domain, recordType, results);
        }

        /// <summary>
        /// Returns line level differences between <paramref name="results"/> and the latest snapshot.
        /// </summary>
        /// <param name="domain">Queried domain name.</param>
        /// <param name="recordType">DNS record type.</param>
        /// <param name="results">Current query results.</param>
        /// <returns>List of diff lines.</returns>
        public IEnumerable<string> GetSnapshotChanges(string domain, DnsRecordType recordType, IEnumerable<DnsPropagationResult> results) {
            return _snapshotManager.GetSnapshotChanges(domain, recordType, results);
        }
    }
}
