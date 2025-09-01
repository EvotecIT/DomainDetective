using DnsClientX;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Checks all MX hosts for STARTTLS support.
        /// </summary>
        public async Task VerifySTARTTLS(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            _logger?.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, port, string.Join(", ", tlsHosts));
            await StartTlsAnalysis.AnalyzeServers(tlsHosts, new[] { port }, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for SMTP TLS configuration.
        /// </summary>
        public async Task VerifySMTPTLS(string domainName, int port, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            _logger?.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, port, string.Join(", ", tlsHosts));
            await SmtpTlsAnalysis.AnalyzeServers(tlsHosts, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for SMTP TLS configuration using the default port.
        /// </summary>
        public Task VerifySMTPTLS(string domainName, CancellationToken cancellationToken = default)
            => VerifySMTPTLS(domainName, 25, cancellationToken);

        /// <summary>
        /// Checks all MX hosts for IMAP TLS configuration.
        /// </summary>
        public async Task VerifyIMAPTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            _logger?.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, 143, string.Join(", ", tlsHosts));
            await ImapTlsAnalysis.AnalyzeServers(tlsHosts, 143, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks all MX hosts for POP3 TLS configuration.
        /// </summary>
        public async Task VerifyPOP3TLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var mxRecordsForTls = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var tlsHosts = CertificateAnalysis.ExtractMxHosts(mxRecordsForTls);
            _logger?.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, 110, string.Join(", ", tlsHosts));
            await Pop3TlsAnalysis.AnalyzeServers(tlsHosts, 110, _logger, cancellationToken);
        }

        /// <summary>
        /// Collects SMTP banners from all MX hosts.
        /// </summary>
        public async Task VerifySMTPBanner(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = CertificateAnalysis.ExtractMxHosts(mx);
            _logger?.WriteVerbose("MX targets for banner check on {0}:{1}: {2}", domainName, port, string.Join(", ", hosts));
            SmtpBannerAnalysis.Subject = domainName;
            await SmtpBannerAnalysis.AnalyzeServers(hosts, port, _logger, cancellationToken);
        }

        /// <summary>
        /// Retrieves SMTP AUTH capabilities from all MX hosts.
        /// </summary>
        public async Task VerifySmtpAuth(string domainName, int port = 25, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var mx = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var hosts = CertificateAnalysis.ExtractMxHosts(mx);
            _logger?.WriteVerbose("MX targets for SMTP AUTH on {0}:{1}: {2}", domainName, port, string.Join(", ", hosts));
            SmtpAuthAnalysis.Subject = domainName;
            await SmtpAuthAnalysis.AnalyzeServers(hosts, port, _logger, cancellationToken);
        }
    }
}
