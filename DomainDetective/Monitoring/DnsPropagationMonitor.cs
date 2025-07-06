using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective.Monitoring {
    /// <summary>Monitors DNS propagation discrepancies over time.</summary>
    /// <para>Part of the DomainDetective project.</para>
    public class DnsPropagationMonitor {
        /// <summary>Domain to query.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>Record type to check.</summary>
        public DnsRecordType RecordType { get; set; } = DnsRecordType.A;

        /// <summary>Interval between checks.</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>Notification sender.</summary>
        public INotificationSender? Notifier { get; set; }

        /// <summary>Override query for testing.</summary>
        public Func<IEnumerable<PublicDnsEntry>, CancellationToken, Task<List<DnsPropagationResult>>>? QueryOverride { private get; set; }

        /// <summary>Country filter for builtin servers.</summary>
        public CountryId? Country { get; set; }

        /// <summary>Location filter for builtin servers.</summary>
        public LocationId? Location { get; set; }

        /// <summary>Additional user supplied servers.</summary>
        public List<PublicDnsEntry> CustomServers { get; } = new();

        /// <summary>Maximum concurrent DNS queries.</summary>
        public int MaxParallelism { get; set; }

        private readonly DnsPropagationAnalysis _analysis = new();
        private Timer? _timer;

        /// <summary>Adds a custom DNS server.</summary>
        /// <param name="entry">Server entry.</param>
        public void AddServer(PublicDnsEntry entry) {
            if (entry != null) {
                CustomServers.Add(entry);
            }
        }

        /// <summary>Starts the monitor.</summary>
        public void Start() {
            Stop();
            _timer = new Timer(async _ => await RunAsync(), null, TimeSpan.Zero, Interval);
        }

        /// <summary>Stops the monitor.</summary>
        public void Stop() {
            _timer?.Dispose();
            _timer = null;
        }

        /// <summary>Loads DNS servers from JSON file.</summary>
        /// <param name="filePath">Path to server list. If null or empty the builtin list is loaded.</param>
        public void LoadServers(string? filePath) {
            if (string.IsNullOrWhiteSpace(filePath)) {
                _analysis.LoadBuiltinServers();
            } else {
                _analysis.LoadServers(filePath, clearExisting: true);
            }
        }

        /// <summary>Loads DNS servers from the embedded list.</summary>
        public void LoadBuiltinServers() => _analysis.LoadBuiltinServers();

        /// <summary>Runs a single propagation check.</summary>
        public async Task RunAsync(CancellationToken ct = default) {
            IEnumerable<PublicDnsEntry> servers = _analysis.FilterServers(Country, Location);
            servers = servers.Concat(CustomServers.Where(s => s.Enabled));
            var serverList = servers.ToList();
            var results = QueryOverride != null
                ? await QueryOverride(serverList, ct)
                : await _analysis.QueryAsync(Domain, RecordType, serverList, ct, null, MaxParallelism);
            var groups = DnsPropagationAnalysis.CompareResults(results);
            if (groups.Count > 1) {
                var message = $"Propagation discrepancy for {Domain} ({RecordType})";
                Console.WriteLine(message);
                if (Notifier != null) {
                    await Notifier.SendAsync(message, ct);
                }
            }
        }
    }
}
