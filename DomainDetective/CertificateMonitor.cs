using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Timer = System.Threading.Timer;

namespace DomainDetective {
    /// <summary>
    /// Aggregates certificate validity information for multiple hosts.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class CertificateMonitor : IDisposable {
        /// <summary>Result entry for a single host.</summary>
        public class Entry {
            /// <summary>Host that was checked.</summary>
            public string Host { get; init; } = string.Empty;
            /// <summary>Certificate expiry date.</summary>
            public DateTime ExpiryDate { get; init; }
            /// <summary>Whether the certificate chain was validated successfully.</summary>
            public bool Valid { get; init; }
            /// <summary>Whether the certificate is expired.</summary>
            public bool Expired { get; init; }
            /// <summary>Whether the certificate chain contained all intermediates.</summary>
            public bool ChainComplete { get; init; }
            /// <summary>Captured analysis details.</summary>
            public CertificateAnalysis Analysis { get; init; }
        }

        private Timer? _timer;
        private IReadOnlyList<string> _monitorHosts = Array.Empty<string>();
        private int _monitorPort;
        private InternalLogger? _monitorLogger;

        /// <summary>Indicates whether monitoring is active.</summary>
        public bool IsRunning => _timer != null;

        /// <summary>Threshold in days for considering a certificate expiring soon.</summary>
        public int ExpiryWarningDays { get; set; } = 30;

        /// <summary>Collection of monitoring results.</summary>
        public List<Entry> Results { get; } = new();

        /// <summary>Begins periodic monitoring of the specified hosts.</summary>
        /// <param name="hosts">Hosts to monitor.</param>
        /// <param name="interval">Interval between checks.</param>
        /// <param name="port">Port used for HTTPS.</param>
        /// <param name="logger">Optional logger instance.</param>
        public void Start(IEnumerable<string> hosts, TimeSpan interval, int port = 443, InternalLogger? logger = null) {
            Stop();
            _monitorHosts = hosts.ToList();
            _monitorPort = port;
            _monitorLogger = logger;
            _timer = new Timer(async _ => await Analyze(_monitorHosts, _monitorPort, _monitorLogger ?? new InternalLogger()), null, TimeSpan.Zero, interval);
        }

        /// <summary>Stops periodic monitoring.</summary>
        public void Stop() {
            _timer?.Dispose();
            _timer = null;
        }

        /// <summary>Checks certificates for the provided hosts.</summary>
        /// <param name="hosts">Hostnames or URLs to verify.</param>
        /// <param name="port">Port used for HTTPS.</param>
        /// <param name="logger">Logger instance for diagnostics.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        public async Task Analyze(IEnumerable<string> hosts, int port = 443, InternalLogger? logger = null, CancellationToken cancellationToken = default) {
            logger ??= new InternalLogger();
            Results.Clear();
            var list = hosts.ToList();
            int processed = 0;
            foreach (var host in list) {
                cancellationToken.ThrowIfCancellationRequested();
                processed++;
                logger.WriteProgress("CertificateMonitor", host, processed * 100 / list.Count, processed, list.Count);
                var analysis = new CertificateAnalysis();
                await analysis.AnalyzeUrl(host, port, logger, cancellationToken);
                var entry = new Entry {
                    Host = host,
                    ExpiryDate = analysis.Certificate?.NotAfter ?? DateTime.MinValue,
                    Valid = analysis.IsValid,
                    Expired = analysis.IsExpired,
                    ChainComplete = analysis.Chain.Count > 1 && analysis.IsValid,
                    Analysis = analysis
                };
                Results.Add(entry);
            }
        }

        /// <summary>Number of hosts with valid certificates.</summary>
        public int ValidCount => Results.Count(e => e.Valid && !e.Expired);
        /// <summary>Number of hosts with certificates expiring soon.</summary>
        public int ExpiringCount => Results.Count(e => e.Valid && !e.Expired && (e.ExpiryDate - DateTime.Now).TotalDays <= ExpiryWarningDays);
        /// <summary>Number of hosts with expired certificates.</summary>
        public int ExpiredCount => Results.Count(e => e.Expired);
        /// <summary>Number of hosts where validation failed.</summary>
        public int FailedCount => Results.Count(e => !e.Valid && !e.Expired && e.Analysis.Certificate == null);

        /// <summary>Number of certificates with complete chains.</summary>
        public int CompleteChainCount => Results.Count(e => e.ChainComplete);
        /// <summary>Number of certificates with incomplete chains.</summary>
        public int IncompleteChainCount => Results.Count(e => !e.ChainComplete && e.Analysis.Certificate != null);
        /// <summary>Number of hosts where the chain status couldn't be determined.</summary>
        public int UnknownChainCount => Results.Count(e => e.Analysis.Certificate == null);

        /// <summary>Disposes timer resources.</summary>
        public void Dispose() {
            Stop();
        }
    }
}
