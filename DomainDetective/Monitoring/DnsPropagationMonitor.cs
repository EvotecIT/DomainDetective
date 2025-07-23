using DnsClientX;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using PeriodicTimer = System.Threading.PeriodicTimer;

namespace DomainDetective.Monitoring {
    /// <summary>Monitors DNS propagation discrepancies over time.</summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Regular queries against a set of public resolvers track how quickly
    /// records spread and highlight inconsistent answers.
    /// </remarks>
    public class DnsPropagationMonitor {
        /// <summary>Domain to query.</summary>
        public string Domain { get; set; } = string.Empty;

        /// <summary>Record type to check.</summary>
        public DnsRecordType RecordType { get; set; } = DnsRecordType.A;

        /// <summary>Interval between checks.</summary>
        public TimeSpan Interval { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>Notification sender.</summary>
        public INotificationSender? Notifier { get; set; }

        /// <summary>Configure a webhook notification.</summary>
        public void UseWebhook(string url)
        {
            Notifier = NotificationSenderFactory.CreateWebhook(url);
        }

        /// <summary>Configure an email notification.</summary>
        public void UseEmail(string smtpHost, int port, bool useSsl, string from, string to, string? username = null, string? password = null)
        {
            Notifier = NotificationSenderFactory.CreateEmail(smtpHost, port, useSsl, from, to, username, password);
        }

        /// <summary>Configure a custom notification handler.</summary>
        public void UseCustom(Func<string, CancellationToken, Task> handler)
        {
            Notifier = NotificationSenderFactory.CreateCustom(handler);
        }

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
        private PeriodicTimer? _timer;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;

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
            _cts = new CancellationTokenSource();
            _timer = new PeriodicTimer(Interval);
            _loopTask = Task.Run(async () => {
                await RunAsync().ConfigureAwait(false);
                while (_timer != null && await _timer.WaitForNextTickAsync(_cts.Token).ConfigureAwait(false)) {
                    await RunAsync().ConfigureAwait(false);
                }
            });
        }

        /// <summary>Stops the monitor.</summary>
        public void Stop() {
            _cts?.Cancel();
            _timer?.Dispose();
            _timer = null;
            _cts?.Dispose();
            _cts = null;
            _loopTask = null;
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
