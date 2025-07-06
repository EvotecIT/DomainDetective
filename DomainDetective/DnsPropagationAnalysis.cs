using DnsClientX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {

    /// <summary>
    /// Provides DNS propagation checks across many public servers.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsPropagationAnalysis {
        private readonly List<PublicDnsEntry> _servers = new();
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
        public IReadOnlyList<PublicDnsEntry> Servers => _servers;

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
                _servers.Clear();
            }

            using var stream = File.OpenRead(filePath);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            options.Converters.Add(new IPAddressJsonConverter());
            var servers = JsonSerializer.DeserializeAsync<List<PublicDnsEntry>>(stream, options)
                .GetAwaiter().GetResult();
            if (servers == null) {
                throw new InvalidDataException("DNS server list is empty or invalid.");
            }

            foreach (var entry in servers) {
                var canonical = GetCanonicalIp(entry.IPAddress);
                if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase)) {
                    throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
                }

                var trimmed = new PublicDnsEntry {
                    Country = entry.Country?.Trim(),
                    IPAddress = entry.IPAddress,
                    HostName = entry.HostName?.Trim(),
                    Location = entry.Location?.Trim(),
                    ASN = entry.ASN,
                    ASNName = entry.ASNName?.Trim(),
                    Enabled = entry.Enabled
                };

                if (_servers.All(s => !s.IPAddress.Equals(trimmed.IPAddress))) {
                    _servers.Add(trimmed);
                }
            }
        }

        /// <summary>
        /// Loads DNS servers from the embedded resource.
        /// </summary>
        /// <param name="clearExisting">Whether to clear existing entries.</param>
        public void LoadBuiltinServers(bool clearExisting = true) {
            if (clearExisting) {
                _servers.Clear();
            }

            using var stream = typeof(DnsPropagationAnalysis).Assembly.GetManifestResourceStream("DomainDetective.DNS.PublicDNS.json");
            if (stream == null) {
                return;
            }

            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            options.Converters.Add(new IPAddressJsonConverter());
            var servers = JsonSerializer.Deserialize<List<PublicDnsEntry>>(json, options);
            if (servers == null) {
                return;
            }

            foreach (var entry in servers) {
                var canonical = GetCanonicalIp(entry.IPAddress);
                if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase)) {
                    throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
                }

                var trimmed = new PublicDnsEntry {
                    Country = entry.Country?.Trim(),
                    IPAddress = entry.IPAddress,
                    HostName = entry.HostName?.Trim(),
                    Location = entry.Location?.Trim(),
                    ASN = entry.ASN,
                    ASNName = entry.ASNName?.Trim(),
                    Enabled = entry.Enabled
                };

                if (_servers.All(s => !s.IPAddress.Equals(trimmed.IPAddress))) {
                    _servers.Add(trimmed);
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

            var canonical = GetCanonicalIp(entry.IPAddress);
            if (!string.Equals(canonical, entry.IPAddress.ToString(), StringComparison.OrdinalIgnoreCase)) {
                throw new FormatException($"Invalid IP address '{entry.IPAddress}'");
            }

            if (_servers.All(s => !s.IPAddress.Equals(entry.IPAddress))) {
                _servers.Add(entry);
            }
        }

        /// <summary>
        /// Removes a DNS server from the list using its IP address.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void RemoveServer(string ipAddress) {
            if (!IPAddress.TryParse(ipAddress, out var parsed)) {
                return;
            }
            var existing = _servers.FirstOrDefault(s => s.IPAddress.Equals(parsed));
            if (existing != null) {
                _servers.Remove(existing);
            }
        }

        /// <summary>
        /// Disables a server so it is not used in queries.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void DisableServer(string ipAddress) {
            if (!IPAddress.TryParse(ipAddress, out var parsed)) {
                return;
            }
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

        /// <summary>
        /// Enables a previously disabled server.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void EnableServer(string ipAddress) {
            if (!IPAddress.TryParse(ipAddress, out var parsed)) {
                return;
            }
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

        /// <summary>
        /// Filters the configured servers optionally by country or location.
        /// </summary>
        /// <param name="country">Country filter.</param>
        /// <param name="location">Location filter.</param>
        /// <param name="take">If specified, randomly selects this many servers.</param>
        /// <returns>The filtered server list.</returns>
        public IEnumerable<PublicDnsEntry> FilterServers(CountryId? country = null, LocationId? location = null, int? take = null) {
            IEnumerable<PublicDnsEntry> query = _servers.Where(s => s.Enabled);
            if (country.HasValue) {
                var name = country.Value.ToName();
                query = query.Where(s => string.Equals(s.Country, name, StringComparison.OrdinalIgnoreCase));
            }
            if (location.HasValue) {
                var name = location.Value.ToName();
                query = query.Where(s => s.Location != null && s.Location.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            if (take.HasValue) {
                query = query.OrderBy(_ => _rnd.Value.Next()).Take(take.Value);
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

        private static string GetCanonicalIp(IPAddress ipAddress) {
            return ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? IPAddress.Parse(ipAddress.ToString()).ToString()
                : ipAddress.ToString();
        }

        /// <summary>
        /// Asynchronously queries each provided server for the specified domain
        /// and record type.
        /// </summary>
        /// <param name="domain">Domain name to query.</param>
        /// <param name="recordType">DNS record type.</param>
        /// <param name="servers">Servers to query.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        /// <returns>A list of query results.</returns>
        public async Task<List<DnsPropagationResult>> QueryAsync(
            string domain,
            DnsRecordType recordType,
            IEnumerable<PublicDnsEntry> servers,
            CancellationToken cancellationToken = default,
            IProgress<double>? progress = null,
            int maxParallelism = 0) {
            var serverList = servers?.ToList() ?? new List<PublicDnsEntry>();
            if (serverList.Count == 0) {
                return new List<DnsPropagationResult>();
            }
            maxParallelism = maxParallelism <= 0 ? serverList.Count : Math.Min(maxParallelism, serverList.Count);

            using var semaphore = new SemaphoreSlim(maxParallelism);
            var tasks = serverList
                .Select(async server => {
                    await semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
                    try {
                        return await QueryServerAsync(domain, recordType, server, cancellationToken).ConfigureAwait(false);
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

        private static async Task<DnsPropagationResult> QueryServerAsync(string domain, DnsRecordType recordType, PublicDnsEntry server, CancellationToken cancellationToken) {
            var sw = Stopwatch.StartNew();
            try {
                var client = new ClientX(server.IPAddress.ToString(), DnsRequestFormat.DnsOverUDP, 53);
                client.EndpointConfiguration.UserAgent = DnsConfiguration.DefaultUserAgent;
                cancellationToken.ThrowIfCancellationRequested();
                var response = await client.Resolve(domain, recordType);
                sw.Stop();
                return new DnsPropagationResult {
                    Server = server,
                    RecordType = recordType,
                    Duration = sw.Elapsed,
                    Records = response.Answers.Select(a => a.Data),
                    Success = response.Answers.Any()
                };
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
                    Records = Array.Empty<string>()
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
            var comparison = new Dictionary<string, List<DnsComparisonEntry>>();
            foreach (var res in results.Where(r => r.Success && r.Records != null)) {
                var normalizedRecords = res.Records
                    .Select(r =>
                        IPAddress.TryParse(r, out var ip)
                            ? ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                                ? IPAddress.Parse(r).ToString().ToLowerInvariant()
                                : ip.ToString()
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
    }
}