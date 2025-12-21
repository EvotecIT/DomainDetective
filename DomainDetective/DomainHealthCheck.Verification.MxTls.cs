using DnsClientX;
using System;
using System.Collections.Generic;
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
            var tlsHosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, port, string.Join(", ", tlsHosts));
            StartTlsAnalysis.Subject = domainName;
            await StartTlsAnalysis.AnalyzeServers(tlsHosts, new[] { port }, _logger, cancellationToken);
            if (StartTlsAnalysis.ServerResults.Count > 0 && StartTlsAnalysis.ServerResults.Values.All(v => v)) {
                _logger.WriteInformationCode(MxCodes.TlsSupported, "All MX hosts support STARTTLS");
            }
        }

        /// <summary>
        /// Checks all MX hosts for SMTP TLS configuration.
        /// </summary>
        public Task VerifySMTPTLS(string domainName, int port, CancellationToken cancellationToken = default)
            => EnsureSmtpTlsAsync(domainName, port, cancellationToken);

        private async Task VerifySmtpTlsInternal(string domainName, int port, CancellationToken cancellationToken) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            ValidatePort(port);
            var tlsHosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, port, string.Join(", ", tlsHosts));
            SmtpTlsAnalysis.Subject = domainName;
            await SmtpTlsAnalysis.AnalyzeServers(tlsHosts, port, _logger, cancellationToken);

            // DANE alignment advisory: if we have DANE results or MX but missing TLSA, or weak TLS under TLSA
            try {
                if (_daneTask != null) {
                    try {
                        await _daneTask;
                    } catch (Exception ex) {
                        _logger.WriteVerbose("DANE task failed for {0}: {1}", domainName, ex.Message);
                    }
                }
                EvaluateDaneAlignment(domainName, tlsHosts);
            } catch (Exception ex) {
                _logger.WriteVerbose("DANE alignment evaluation failed for {0}: {1}", domainName, ex.Message);
            }
        }

        /// <summary>
        /// Checks all MX hosts for SMTP TLS configuration using the default port.
        /// </summary>
        public Task VerifySMTPTLS(string domainName, CancellationToken cancellationToken = default)
            => VerifySMTPTLS(domainName, 25, cancellationToken);

        private void EvaluateDaneAlignment(string domainName, IEnumerable<string> mxHosts) {
            var hosts = mxHosts?.ToArray() ?? Array.Empty<string>();
            if (hosts.Length == 0) {
                return;
            }
            var hasSmtpTlsa = DaneAnalysis?.AnalysisResults?.Any(r => r.ServiceType == ServiceType.SMTP) == true;
            if (!hasSmtpTlsa) {
                _logger.WriteWarningCode(DaneCodes.AlignmentMissingForMx, "No TLSA coverage for MX hosts on {0}", domainName);
                return;
            }
            // If TLSA exists, ensure TLS posture is not weak
            var weak = SmtpTlsAnalysis?.ServerResults?.Values?.Any(r =>
                r == null || r.LegacyEnabled || !r.CertificateValid || !r.ChainValid || !r.HostnameMatch || r.GradeLevel.IsBelow(GradeLevel.B)) == true;
            if (weak) {
                _logger.WriteWarningCode(DaneCodes.AlignmentTlsWeak, "TLSA present but negotiated TLS is weak on some MX hosts");
            }
        }

        /// <summary>
        /// Checks all MX hosts for IMAP TLS configuration.
        /// </summary>
        public async Task VerifyIMAPTLS(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            var tlsHosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, 143, string.Join(", ", tlsHosts));
            ImapTlsAnalysis.Subject = domainName;
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
            var tlsHosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for {0} on port {1}: {2}", domainName, 110, string.Join(", ", tlsHosts));
            Pop3TlsAnalysis.Subject = domainName;
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
            var hosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for banner check on {0}:{1}: {2}", domainName, port, string.Join(", ", hosts));
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
            var hosts = await GetMxHostsAsync(domainName, cancellationToken);
            _logger.WriteVerbose("MX targets for SMTP AUTH on {0}:{1}: {2}", domainName, port, string.Join(", ", hosts));
            SmtpAuthAnalysis.Subject = domainName;
            await SmtpAuthAnalysis.AnalyzeServers(hosts, port, _logger, cancellationToken);
        }
    }
}
