using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective {
    /// <summary>
    /// Checks whether SMTP servers advertise the STARTTLS capability.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
public class STARTTLSAnalysis : IHasAssessments {
        /// <summary>Gets or sets the subject value.</summary>
        public string? Subject { get; set; }
        /// <summary>Gets or sets the server results value.</summary>
        public Dictionary<string, bool> ServerResults { get; private set; } = new();
        /// <summary>Gets or sets the downgrade detected value.</summary>
        public Dictionary<string, bool> DowngradeDetected { get; private set; } = new();
        /// <summary>Gets or sets the server details value.</summary>
        public Dictionary<string, STARTTLSResult> ServerDetails { get; private set; } = new();
        /// <summary>Gets or sets the timeout value.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>Structured assessments during STARTTLS probe.</summary>
        public List<Assessment> Assessments { get; } = new();
        /// <summary>Represents the recommendations value.</summary>
        public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

        /// <summary>
        /// Tests a single server for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            DowngradeDetected.Clear();
            ServerDetails.Clear();
            cancellationToken.ThrowIfCancellationRequested();
            var detail = await CheckStartTls(host, port, logger, cancellationToken);
            var key = $"{host}:{port}";
            ServerResults[key] = detail.StartTlsAdvertised || detail.TlsNegotiated;
            DowngradeDetected[key] = detail.DowngradeDetected;
            ServerDetails[key] = detail;
        }

        /// <summary>
        /// Tests multiple servers for STARTTLS support.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, IEnumerable<int> ports, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            DowngradeDetected.Clear();
            ServerDetails.Clear();
            foreach (var host in hosts) {
                foreach (var port in ports) {
                    cancellationToken.ThrowIfCancellationRequested();
                    var detail = await CheckStartTls(host, port, logger, cancellationToken);
                    var key = $"{host}:{port}";
                    ServerResults[key] = detail.StartTlsAdvertised || detail.TlsNegotiated;
                    DowngradeDetected[key] = detail.DowngradeDetected;
                    ServerDetails[key] = detail;
                }
            }
        }

        /// <summary>
        /// Resolves the specified host and returns a <see cref="DnsEndPoint"/>
        /// with address family information when an IP address is provided.
        /// </summary>
        private static DnsEndPoint GetEndPoint(string host, int port) {
            return IPAddress.TryParse(host, out IPAddress? ip)
                ? new DnsEndPoint(host, port, ip.AddressFamily)
                : new DnsEndPoint(host, port);
        }

        /// <summary>
        /// Performs the low-level STARTTLS negotiation.
        /// </summary>
        private async Task<STARTTLSResult> CheckStartTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "STARTTLS", target: $"{host}:{port}");
            var endPoint = GetEndPoint(host, port);
            var client = endPoint.AddressFamily == AddressFamily.Unspecified
                ? new TcpClient()
                : new TcpClient(endPoint.AddressFamily);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
                if (endPoint.AddressFamily == AddressFamily.Unspecified) {
                    await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
                } else {
                    await client.Client.ConnectAsync(endPoint).WaitWithCancellation(timeoutCts.Token);
                }
                using NetworkStream network = client.GetStream();
                using var reader = new StreamReader(network);
                using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };

                var banner = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                timeoutCts.Token.ThrowIfCancellationRequested();
                bool bannerDowngrade = false;
                if (banner == null || !banner.StartsWith("220")) {
                    if (banner != null && banner.IndexOf("TLS", System.StringComparison.OrdinalIgnoreCase) >= 0) {
                        bannerDowngrade = true;
                    }
                    logger?.WriteWarningCode(StartTlsCodes.BannerUnexpected, $"Unexpected banner sequence: {banner}");
                }
                await writer.WriteLineAsync($"EHLO example.com");

                var capabilities = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);
                var ehloLines = new List<string>();
                string? line;
                string? lastEhlo = null;
                while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    logger?.WriteVerbose($"EHLO response: {line}");
                    ehloLines.Add(line);
                    if (line.StartsWith("250")) {
                        string capabilityLine = line.Substring(4).Trim();
                        foreach (var part in capabilityLine.Split(new[] { ' ' }, System.StringSplitOptions.RemoveEmptyEntries)) {
                            capabilities.Add(part);
                        }
                        lastEhlo = line;
                        if (!line.StartsWith("250-")) {
                            break;
                        }
                    } else if (line.StartsWith("5") || line.StartsWith("4")) {
                        logger?.WriteWarningCode(StartTlsCodes.EhloUnexpected, $"Unexpected EHLO response: {line}");
                        break;
                    }
                }

                if (lastEhlo != null && lastEhlo.StartsWith("250-")) {
                    logger?.WriteWarningCode(StartTlsCodes.EhloMissingFinal250, "EHLO response ended without final 250 line");
                }

                bool advertised = capabilities.Contains("STARTTLS");
                bool supports = advertised;
                bool attempted = false;
                bool tlsOk = false;
                string? proto = null;
                string? resultCipherAlg = null;
                int? resultCipherStrength = null;
                string? resultHashAlg = null;
                int? resultHashStrength = null;
                string? resultKeyExAlg = null;
                int? resultKeyExStrength = null;
                string? resultAlpn = null;
                string? resultCertSubject = null;
                string? resultCertIssuer = null;
                DateTime? resultCertNotBefore = null;
                DateTime? resultCertNotAfter = null;
                string? resultCertThumbprint = null;

                // Only attempt STARTTLS when it is not advertised to detect hidden support (downgrade scenarios).
                if (!advertised) {
                    await writer.WriteLineAsync("STARTTLS");
                    var resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                    if (resp != null && resp.StartsWith("220")) {
                    try {
                        using var ssl = new System.Net.Security.SslStream(network, false, static (_, _, _, _) => true);
                        await ssl.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
                        using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                        await secureWriter.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                        supports = true;
                        attempted = true;
                        tlsOk = true;
#if NET8_0_OR_GREATER
                        proto = ssl.SslProtocol.ToString();
#endif
                        // Capture cipher/algorithms and certificate metadata
                        var tlsInfo = TlsNegotiationInfoFactory.Create(ssl);
                        resultCipherAlg = tlsInfo.CipherAlgorithm;
                        resultCipherStrength = tlsInfo.CipherStrength;
                        resultHashAlg = tlsInfo.HashAlgorithm;
                        resultHashStrength = tlsInfo.HashStrength;
                        resultKeyExAlg = tlsInfo.KeyExchangeAlgorithm;
                        resultKeyExStrength = tlsInfo.KeyExchangeStrength;
#if NET8_0_OR_GREATER
                        var nap = ssl.NegotiatedApplicationProtocol;
                        if (!nap.Protocol.IsEmpty) {
                            try { resultAlpn = System.Text.Encoding.ASCII.GetString(nap.Protocol.Span); } catch { }
                        }
#endif
                        try {
                            var remoteCertificate = ssl.RemoteCertificate;
                            if (remoteCertificate != null)
                            {
                                var cert = remoteCertificate as System.Security.Cryptography.X509Certificates.X509Certificate2 ??
                                           new System.Security.Cryptography.X509Certificates.X509Certificate2(remoteCertificate);
                                resultCertSubject = cert.Subject;
                                resultCertIssuer = cert.Issuer;
                                resultCertNotBefore = cert.NotBefore;
                                resultCertNotAfter = cert.NotAfter;
                                resultCertThumbprint = cert.Thumbprint;
                            }
                        } catch { }
                    } catch (Exception ex) {
                        logger?.WriteVerbose($"STARTTLS handshake failed for {host}:{port} - {ex.Message}");
                    }
                    }
                }

                bool downgrade = bannerDowngrade || (!advertised && tlsOk);

                if (!attempted && (advertised || !downgrade)) {
                    await writer.WriteLineAsync("QUIT");
                    await writer.FlushAsync();
                    try {
                        await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                    } catch (IOException) {
                        // swallow disconnect after QUIT
                    }
                }

                return new STARTTLSResult {
                    Host = host,
                    Port = port,
                    Banner = banner ?? string.Empty,
                    EhloLines = ehloLines,
                    Capabilities = new List<string>(capabilities),
                    StartTlsAdvertised = advertised,
                    DowngradeDetected = downgrade,
                    StartTlsAttempted = attempted,
                    TlsNegotiated = tlsOk,
                    TlsProtocol = proto,
                    CipherAlgorithm = resultCipherAlg,
                    CipherStrength = resultCipherStrength,
                    HashAlgorithm = resultHashAlg,
                    HashStrength = resultHashStrength,
                    KeyExchangeAlgorithm = resultKeyExAlg,
                    KeyExchangeStrength = resultKeyExStrength,
                    AlpnProtocol = resultAlpn,
                    CertificateSubject = resultCertSubject,
                    CertificateIssuer = resultCertIssuer,
                    CertificateNotBefore = resultCertNotBefore,
                    CertificateNotAfter = resultCertNotAfter,
                    CertificateThumbprint = resultCertThumbprint,
                };
            } catch (System.Exception ex) {
                logger?.WriteErrorCode(StartTlsCodes.CheckFailed, "STARTTLS check failed for {0}:{1} - {2}", host, port, ex.Message);
                return new STARTTLSResult {
                    Host = host,
                    Port = port,
                    Banner = string.Empty,
                    EhloLines = new List<string>(),
                    Capabilities = new List<string>(),
                    StartTlsAdvertised = false,
                    DowngradeDetected = false,
                    StartTlsAttempted = false,
                    TlsNegotiated = false,
                };
            } finally {
                client.Dispose();
            }
        }
    }

    /// <summary>Detailed STARTTLS probe result per server.</summary>
    public sealed class STARTTLSResult {
        /// <summary>Gets or sets the host value.</summary>
        public string Host { get; set; } = string.Empty;
        /// <summary>Gets or sets the port value.</summary>
        public int Port { get; set; }
        /// <summary>Gets or sets the banner value.</summary>
        public string Banner { get; set; } = string.Empty;
        /// <summary>Gets or sets the ehlo lines value.</summary>
        public List<string> EhloLines { get; set; } = new List<string>();
        /// <summary>Gets or sets the capabilities value.</summary>
        public List<string> Capabilities { get; set; } = new List<string>();
        /// <summary>Gets or sets the start tls advertised value.</summary>
        public bool StartTlsAdvertised { get; set; }
        /// <summary>Gets or sets the downgrade detected value.</summary>
        public bool DowngradeDetected { get; set; }
        /// <summary>Gets or sets the start tls attempted value.</summary>
        public bool StartTlsAttempted { get; set; }
        /// <summary>Gets or sets the tls negotiated value.</summary>
        public bool TlsNegotiated { get; set; }
        /// <summary>Gets or sets the tls protocol value.</summary>
        public string? TlsProtocol { get; set; }
        /// <summary>Gets or sets the cipher algorithm value.</summary>
        public string? CipherAlgorithm { get; set; }
        /// <summary>Gets or sets the cipher strength value.</summary>
        public int? CipherStrength { get; set; }
        /// <summary>Gets or sets the hash algorithm value.</summary>
        public string? HashAlgorithm { get; set; }
        /// <summary>Gets or sets the hash strength value.</summary>
        public int? HashStrength { get; set; }
        /// <summary>Gets or sets the key exchange algorithm value.</summary>
        public string? KeyExchangeAlgorithm { get; set; }
        /// <summary>Gets or sets the key exchange strength value.</summary>
        public int? KeyExchangeStrength { get; set; }
        /// <summary>Gets or sets the alpn protocol value.</summary>
        public string? AlpnProtocol { get; set; }
        /// <summary>Gets or sets the certificate subject value.</summary>
        public string? CertificateSubject { get; set; }
        /// <summary>Gets or sets the certificate issuer value.</summary>
        public string? CertificateIssuer { get; set; }
        /// <summary>Gets or sets the certificate not before value.</summary>
        public DateTime? CertificateNotBefore { get; set; }
        /// <summary>Gets or sets the certificate not after value.</summary>
        public DateTime? CertificateNotAfter { get; set; }
        /// <summary>Gets or sets the certificate thumbprint value.</summary>
        public string? CertificateThumbprint { get; set; }
    }
}
