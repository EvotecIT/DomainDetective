using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

namespace DomainDetective {
    public class PublicDnsEntry {
        public string Country { get; set; }
        public string IPAddress { get; set; }
        public string HostName { get; set; }
        public string Location { get; set; }
        public string ASN { get; set; }
        public string ASNName { get; set; }
        public bool Enabled { get; set; } = true;
    }

    public class DnsPropagationResult {
        public PublicDnsEntry Server { get; set; }
        public IEnumerable<string> Records { get; set; }
        public TimeSpan Duration { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    public class DnsPropagationAnalysis {
        private readonly List<PublicDnsEntry> _servers = new();

        public IReadOnlyList<PublicDnsEntry> Servers => _servers;

        public void LoadServers(string filePath, bool clearExisting = false) {
            if (!File.Exists(filePath)) {
                throw new FileNotFoundException($"DNS server list file not found: {filePath}");
            }

            if (clearExisting) {
                _servers.Clear();
            }

            var json = File.ReadAllText(filePath);
            var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
            var servers = JsonSerializer.Deserialize<List<PublicDnsEntry>>(json, options);
            if (servers == null) {
                return;
            }
            foreach (var entry in servers) {
                if (_servers.All(s => s.IPAddress != entry.IPAddress)) {
                    _servers.Add(entry);
                }
            }
        }

        public void AddServer(PublicDnsEntry entry) {
            if (entry == null || string.IsNullOrWhiteSpace(entry.IPAddress)) {
                return;
            }
            if (_servers.All(s => s.IPAddress != entry.IPAddress)) {
                _servers.Add(entry);
            }
        }

        public void RemoveServer(string ipAddress) {
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
            if (existing != null) {
                _servers.Remove(existing);
            }
        }

        public void DisableServer(string ipAddress) {
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
            if (existing != null) {
                existing.Enabled = false;
            }
        }

        public void EnableServer(string ipAddress) {
            var existing = _servers.FirstOrDefault(s => s.IPAddress == ipAddress);
            if (existing != null) {
                existing.Enabled = true;
            }
        }

        public IEnumerable<PublicDnsEntry> FilterServers(string country = null, string location = null, int? take = null) {
            IEnumerable<PublicDnsEntry> query = _servers.Where(s => s.Enabled);
            if (!string.IsNullOrWhiteSpace(country)) {
                query = query.Where(s => string.Equals(s.Country, country, StringComparison.OrdinalIgnoreCase));
            }
            if (!string.IsNullOrWhiteSpace(location)) {
                query = query.Where(s => s.Location != null && s.Location.IndexOf(location, StringComparison.OrdinalIgnoreCase) >= 0);
            }
            if (take.HasValue) {
                var rnd = new Random();
                query = query.OrderBy(_ => rnd.Next()).Take(take.Value);
            }
            return query.ToList();
        }

        public async Task<List<DnsPropagationResult>> QueryAsync(string domain, DnsRecordType recordType, IEnumerable<PublicDnsEntry> servers, CancellationToken cancellationToken = default) {
            var results = new List<DnsPropagationResult>();
            var tasks = servers.Select(server => QueryServerAsync(domain, recordType, server, cancellationToken));
            results.AddRange(await Task.WhenAll(tasks));
            return results;
        }

        private static async Task<DnsPropagationResult> QueryServerAsync(string domain, DnsRecordType recordType, PublicDnsEntry server, CancellationToken cancellationToken) {
            var result = new DnsPropagationResult { Server = server, Success = false, Records = Array.Empty<string>() };
            var sw = Stopwatch.StartNew();
            try {
                var client = new ClientX(server.IPAddress, DnsRequestFormat.DnsOverUDP, 53);
                cancellationToken.ThrowIfCancellationRequested();
                var response = await client.Resolve(domain, recordType);
                sw.Stop();
                result.Duration = sw.Elapsed;
                result.Records = response.Answers.Select(a => a.Data);
                result.Success = response.Answers.Any();
            } catch (Exception ex) {
                sw.Stop();
                result.Duration = sw.Elapsed;
                result.Error = ex.Message;
            }
            return result;
        }

        public static Dictionary<string, List<PublicDnsEntry>> CompareResults(IEnumerable<DnsPropagationResult> results) {
            var comparison = new Dictionary<string, List<PublicDnsEntry>>();
            foreach (var res in results.Where(r => r.Success)) {
                var key = string.Join(",", res.Records.OrderBy(r => r));
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
