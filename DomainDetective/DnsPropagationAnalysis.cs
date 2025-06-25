using DnsClientX;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.IO.Compression;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Represents a public DNS server used for propagation checks.
    /// </summary>
    public class PublicDnsEntry {
        /// <summary>Gets the country of the DNS server.</summary>
        public string Country { get; init; }
        /// <summary>Gets the IP address of the DNS server.</summary>
        public string IPAddress { get; init; }
        /// <summary>Gets the host name of the DNS server.</summary>
        public string HostName { get; init; }
        /// <summary>Gets the location description.</summary>
        public string Location { get; init; }
        /// <summary>Gets the ASN of the DNS server.</summary>
        public string ASN { get; init; }
        /// <summary>Gets the ASN name of the DNS server.</summary>
        public string ASNName { get; init; }
        /// <summary>Gets a value indicating whether the server is enabled.</summary>
        public bool Enabled { get; init; } = true;
    }

    /// <summary>
    /// Result of a DNS propagation query for a single server.
    /// </summary>
    public class DnsPropagationResult {
        /// <summary>Gets the server that was queried.</summary>
        public PublicDnsEntry Server { get; init; }
        /// <summary>Gets the records returned by the server.</summary>
        public IEnumerable<string> Records { get; init; }
        /// <summary>Gets the time the query took.</summary>
        public TimeSpan Duration { get; init; }
        /// <summary>Gets a value indicating whether the query succeeded.</summary>
        public bool Success { get; init; }
        /// <summary>Gets an error message if the query failed.</summary>
        public string Error { get; init; }
    }

    /// <summary>
    /// Provides DNS propagation checks across many public servers.
    /// </summary>
    public class DnsPropagationAnalysis {
        private readonly List<PublicDnsEntry> _servers = new();
        /// <summary>
        /// Random number generator used for selecting a subset of servers.
        /// </summary>
        /// <remarks>
        /// <para>This instance is shared and not thread-safe. Callers must
        /// synchronize access when <see cref="FilterServers"/> is used concurrently.</para>
        /// </remarks>
        private static readonly Random _rnd = new();

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

            using var stream = File.OpenRead(filePath);
            LoadServers(stream, clearExisting);
        }

        /// <summary>
        /// Loads DNS server definitions from a stream containing JSON.
        /// </summary>
        /// <param name="stream">The stream with JSON data.</param>
        /// <param name="clearExisting">Whether to clear any existing servers before loading.</param>
        public void LoadServers(Stream stream, bool clearExisting = false) {
            if (stream == null) {
                throw new ArgumentNullException(nameof(stream));
            }

            using var reader = new StreamReader(stream);
            var json = reader.ReadToEnd();
            LoadServersFromJson(json, clearExisting);
        }

        /// <summary>
        /// Loads DNS server definitions embedded within the assembly.
        /// </summary>
        /// <param name="clearExisting">Whether to clear any existing servers before loading.</param>
        public void LoadBuiltInServers(bool clearExisting = false) {
            var assembly = typeof(DnsPropagationAnalysis).Assembly;
            using var stream = assembly.GetManifestResourceStream("Data.PublicDNS.json.gz");
            if (stream == null) {
                return;
            }
            using var gzip = new GZipStream(stream, CompressionMode.Decompress);
            LoadServers(gzip, clearExisting);
        }

        /// <summary>
        /// Loads DNS server definitions from a URI.
        /// </summary>
        /// <param name="uri">HTTP or HTTPS URL to a JSON file.</param>
        /// <param name="clearExisting">Whether to clear any existing servers before loading.</param>
        public async Task LoadServersFromUriAsync(string uri, bool clearExisting = false) {
            using var client = new HttpClient();
            var json = await client.GetStringAsync(uri).ConfigureAwait(false);
            LoadServersFromJson(json, clearExisting);
        }

        private void LoadServersFromJson(string json, bool clearExisting) {
            if (clearExisting) {
                _servers.Clear();
            }

            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var servers = JsonSerializer.Deserialize<List<PublicDnsEntry>>(json, options);
            if (servers == null) {
                return;
            }

            foreach (var entry in servers) {
                var trimmed = new PublicDnsEntry {
                    Country = entry.Country?.Trim(),
                    IPAddress = entry.IPAddress,
                    HostName = entry.HostName?.Trim(),
                    Location = entry.Location?.Trim(),
                    ASN = entry.ASN,
                    ASNName = entry.ASNName?.Trim(),
                    Enabled = entry.Enabled
                };

                if (_servers.All(s => s.IPAddress != trimmed.IPAddress)) {
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
            if (entry == null || string.IsNullOrWhiteSpace(entry.IPAddress)) {
                return;
            }
            if (_servers.All(s => s.IPAddress != entry.IPAddress)) {
                _servers.Add(entry);
            }
        }

        /// <summary>
        /// Removes a DNS server from the list using its IP address.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void RemoveServer(string ipAddress) {
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
            if (existing != null) {
                _servers.Remove(existing);
            }
        }

        /// <summary>
        /// Disables a server so it is not used in queries.
        /// </summary>
        /// <param name="ipAddress">IP address of the server.</param>
        public void DisableServer(string ipAddress) {
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
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
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
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
        public IEnumerable<PublicDnsEntry> FilterServers(string country = null, string location = null, int? take = null) {
            IEnumerable<PublicDnsEntry> query = _servers.Where(s => s.Enabled);
            if (!string.IsNullOrWhiteSpace(country)) {
                query = query.Where(s => string.Equals(s.Country, country, StringComparison.OrdinalIgnoreCase));
            }
            if (!string.IsNullOrWhiteSpace(location)) {
                query = query.Where(s => s.Location != null && s.Location.IndexOf(location, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            if (take.HasValue) {
                query = query.OrderBy(_ => _rnd.Next()).Take(take.Value);
            }
            return query.ToList();
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
        public async Task<List<DnsPropagationResult>> QueryAsync(string domain, DnsRecordType recordType, IEnumerable<PublicDnsEntry> servers, CancellationToken cancellationToken = default) {
            var results = new List<DnsPropagationResult>();
            var tasks = servers.Select(server => QueryServerAsync(domain, recordType, server, cancellationToken));
            results.AddRange(await Task.WhenAll(tasks));
            return results;
        }

        private static async Task<DnsPropagationResult> QueryServerAsync(string domain, DnsRecordType recordType, PublicDnsEntry server, CancellationToken cancellationToken) {
            var sw = Stopwatch.StartNew();
            try {
                var client = new ClientX(server.IPAddress, DnsRequestFormat.DnsOverUDP, 53);
                cancellationToken.ThrowIfCancellationRequested();
                var response = await client.Resolve(domain, recordType);
                sw.Stop();
                return new DnsPropagationResult {
                    Server = server,
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
        /// <returns>A dictionary keyed by the record returned and listing the servers that returned it.</returns>
        public static Dictionary<string, List<PublicDnsEntry>> CompareResults(IEnumerable<DnsPropagationResult> results) {
            var comparison = new Dictionary<string, List<PublicDnsEntry>>();
            foreach (var res in results.Where(r => r.Success && r.Records != null)) {
                var normalizedRecords = res.Records
                    .Select(r =>
                        IPAddress.TryParse(r, out var ip)
                            ? ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                                ? ip.ToString().ToLowerInvariant()
                                : ip.ToString()
                            : r)
                    .OrderBy(r => r);
                var key = string.Join(",", normalizedRecords);
                if (!comparison.TryGetValue(key, out var list)) {
                    list = new List<PublicDnsEntry>();
                    comparison[key] = list;
                }
                list.Add(res.Server);
            }
            return comparison;
        }
    }
}