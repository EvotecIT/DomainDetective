using PortScanProfile = DomainDetective.PortScanProfileDefinition.PortScanProfile;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Tests an SMTP server for open relay configuration.
        /// </summary>
        /// <param name="host">Target host name.</param>
        /// <param name="port">Port to connect to. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckOpenRelayHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await OpenRelayAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks if a DNS server allows recursive queries.
        /// </summary>
        /// <param name="host">Target server host name or IP.</param>
        /// <param name="port">DNS port number. Must be between 1 and 65535.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task CheckOpenResolverHost(string host, int port = 53, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await OpenResolverAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for STARTTLS support.
        /// </summary>
        public async Task CheckStartTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            ApplyOutboundAddressResolver(StartTlsAnalysis);
            await StartTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks an explicitly targeted host for STARTTLS support while preserving the logical hostname.
        /// </summary>
        public async Task CheckStartTlsHost(MailTransportEndpoint endpoint, CancellationToken cancellationToken = default) {
            if (endpoint == null) {
                throw new System.ArgumentNullException(nameof(endpoint));
            }
            ValidatePort(endpoint.Port);
            ApplyOutboundAddressResolver(StartTlsAnalysis);
            await StartTlsAnalysis.AnalyzeServer(endpoint, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for SMTP TLS capabilities.
        /// </summary>
        public async Task CheckSmtpTlsHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            ApplyOutboundAddressResolver(SmtpTlsAnalysis);
            await SmtpTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks an explicitly targeted host for SMTP TLS capabilities while preserving the logical hostname.
        /// </summary>
        public async Task CheckSmtpTlsHost(MailTransportEndpoint endpoint, CancellationToken cancellationToken = default) {
            if (endpoint == null) {
                throw new System.ArgumentNullException(nameof(endpoint));
            }
            ValidatePort(endpoint.Port);
            ApplyOutboundAddressResolver(SmtpTlsAnalysis);
            await SmtpTlsAnalysis.AnalyzeServer(endpoint, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for IMAP TLS capabilities.
        /// </summary>
        public async Task CheckImapTlsHost(string host, int port = 143, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            ApplyOutboundAddressResolver(ImapTlsAnalysis);
            await ImapTlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks an explicitly targeted host for IMAP TLS capabilities while preserving the logical hostname.
        /// </summary>
        public async Task CheckImapTlsHost(MailTransportEndpoint endpoint, CancellationToken cancellationToken = default) {
            if (endpoint == null) {
                throw new System.ArgumentNullException(nameof(endpoint));
            }
            ValidatePort(endpoint.Port);
            ApplyOutboundAddressResolver(ImapTlsAnalysis);
            await ImapTlsAnalysis.AnalyzeServer(endpoint, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for POP3 TLS capabilities.
        /// </summary>
        public async Task CheckPop3TlsHost(string host, int port = 110, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            ApplyOutboundAddressResolver(Pop3TlsAnalysis);
            await Pop3TlsAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks an explicitly targeted host for POP3 TLS capabilities while preserving the logical hostname.
        /// </summary>
        public async Task CheckPop3TlsHost(MailTransportEndpoint endpoint, CancellationToken cancellationToken = default) {
            if (endpoint == null) {
                throw new System.ArgumentNullException(nameof(endpoint));
            }
            ValidatePort(endpoint.Port);
            ApplyOutboundAddressResolver(Pop3TlsAnalysis);
            await Pop3TlsAnalysis.AnalyzeServer(endpoint, _logger, cancellationToken);
        }

        /// <summary>
        /// Retrieves the SMTP banner from a host.
        /// </summary>
        public async Task CheckSmtpBannerHost(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            SmtpBannerAnalysis.Subject = $"{host}:{port}";
            await SmtpBannerAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Measures mail server connection and banner latency.
        /// </summary>
        public async Task CheckMailLatency(string host, int port = 25, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await MailLatencyAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Tests connectivity to common service ports on a host.
        /// </summary>
        public async Task CheckPortAvailability(string host, IEnumerable<int>? ports = null, CancellationToken cancellationToken = default) {
            var list = ports?.ToArray() ?? new[] { 25, 80, 443, 465, 587 };
            foreach (var p in list) {
                ValidatePort(p);
            }
            await PortAvailabilityAnalysis.AnalyzeServers(new[] { host }, list, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks a host for SNMP responses.
        /// </summary>
        public async Task CheckSnmpHost(string host, int port = 161, CancellationToken cancellationToken = default) {
            ValidatePort(port);
            await SnmpAnalysis.AnalyzeServer(host, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Scans a host for open TCP and UDP ports.
        /// </summary>
        public async Task ScanPorts(string host, IEnumerable<int>? ports = null, PortScanProfile[]? profiles = null, CancellationToken cancellationToken = default, bool showProgress = true) {
            IEnumerable<int> selected;
            if (ports != null && ports.Any()) {
                selected = ports;
            } else if (profiles != null && profiles.Length > 0) {
                selected = profiles.SelectMany(PortScanProfileDefinition.GetPorts).Distinct();
            } else {
                selected = PortScanProfileDefinition.DefaultPorts;
            }
            var list = selected.ToArray();
            foreach (var p in list) {
                ValidatePort(p);
            }
            await PortScanAnalysis.Scan(host, list, _logger, cancellationToken, showProgress);
        }

        /// <summary>Queries neighbors sharing the same IP as <paramref name="domainName"/>.</summary>
        public async Task CheckIPNeighbors(string domainName, CancellationToken cancellationToken = default) {
            await IPNeighborAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
        /// <summary>Queries neighbors for IPs used by MX hosts of <paramref name="domainName"/>.</summary>
        public async Task CheckMailIPNeighbors(string domainName, CancellationToken cancellationToken = default) {
            await IPNeighborAnalysis.AnalyzeMx(domainName, _logger, cancellationToken);
        }

        private void ApplyOutboundAddressResolver(STARTTLSAnalysis analysis) {
            if (OutboundAddressResolver != null) {
                analysis.OutboundAddressResolver = OutboundAddressResolver;
            }
        }

        private void ApplyOutboundAddressResolver(MailTlsAnalysis analysis) {
            if (OutboundAddressResolver != null) {
                analysis.OutboundAddressResolver = OutboundAddressResolver;
            }
        }
    }
}
