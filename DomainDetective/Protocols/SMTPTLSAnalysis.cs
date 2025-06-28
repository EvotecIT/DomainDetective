using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    /// <summary>
    /// Inspects SMTP servers for TLS configuration details.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    public class SMTPTLSAnalysis {
        /// <summary>
        /// Holds TLS negotiation results for a single server.
        /// </summary>
        /// <para>Part of the DomainDetective project.</para>
        public class TlsResult {
            public bool StartTlsAdvertised { get; set; }
            public bool CertificateValid { get; set; }
            public int DaysToExpire { get; set; }
            public SslProtocols Protocol { get; set; }
            public bool SupportsTls13 { get; set; }
            public CipherAlgorithmType CipherAlgorithm { get; set; }
            public int CipherStrength { get; set; }
            public string CipherSuite { get; set; } = string.Empty;
            public int DhKeyBits { get; set; }
            public List<X509Certificate2> Chain { get; } = new();
            public List<X509ChainStatusFlags> ChainErrors { get; } = new();
        }

        public Dictionary<string, TlsResult> ServerResults { get; } = new();
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Analyzes TLS settings for a single SMTP server.
        /// </summary>
        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            var result = await CheckTls(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = result;
        }

        /// <summary>
        /// Analyzes TLS settings for multiple SMTP servers.
        /// </summary>
        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                ServerResults[$"{host}:{port}"] = await CheckTls(host, port, logger, cancellationToken);
            }
        }

        /// <summary>
        /// Performs the TLS handshake and collects certificate details.
        /// </summary>
        private async Task<TlsResult> CheckTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            var result = new TlsResult();
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(Timeout);
            try {
                using (var client = new TcpClient()) {
#if NET6_0_OR_GREATER
                    await client.ConnectAsync(host, port, timeoutCts.Token);
#else
                    await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
#endif

                    using NetworkStream network = client.GetStream();
                    using (var reader = new StreamReader(network))
                    using (var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" }) {
#if NET8_0_OR_GREATER
                        await reader.ReadLineAsync(timeoutCts.Token);
#else
                        await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        await writer.WriteLineAsync($"EHLO example.com");

                        var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        string line;
                        while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                            timeoutCts.Token.ThrowIfCancellationRequested();
                            logger?.WriteVerbose($"EHLO response: {line}");
                            if (line.StartsWith("250")) {
                                string capabilityLine = line.Substring(4).Trim();
                                foreach (var part in capabilityLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
                                    capabilities.Add(part);
                                }
                                if (!line.StartsWith("250-")) {
                                    break;
                                }
                            } else if (line.StartsWith("4") || line.StartsWith("5")) {
                                break;
                            }
                        }

                        result.StartTlsAdvertised = capabilities.Contains("STARTTLS");
                        if (!result.StartTlsAdvertised) {
                            await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                            await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                            await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                            return result;
                        }

                        await writer.WriteLineAsync("STARTTLS").WaitWithCancellation(timeoutCts.Token);
                        string resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                        if (resp == null || !resp.StartsWith("220")) {
                            logger?.WriteVerbose($"{host}:{port} STARTTLS rejected: {resp}");
                            return result;
                        }

                        using var ssl = new SslStream(network, false, (sender, certificate, chain, errors) => {
                            result.CertificateValid = errors == SslPolicyErrors.None;
                            result.Chain.Clear();
                            result.ChainErrors.Clear();
                            if (certificate is X509Certificate2 cert) {
                                result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                                if (chain != null) {
                                    foreach (var element in chain.ChainElements) {
                                        result.Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                                    }
                                    foreach (var status in chain.ChainStatus) {
                                        result.ChainErrors.Add(status.Status);
                                    }
                                }
                            }
                            return true;
                        });

                        try {
#if NET8_0_OR_GREATER
                            await ssl.AuthenticateAsClientAsync(host, null, SslProtocols.Tls13 | SslProtocols.Tls12, false)
                                .WaitWithCancellation(timeoutCts.Token);
#else
                            await ssl.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
#endif
                            result.CipherAlgorithm = ssl.CipherAlgorithm;
                            result.CipherStrength = ssl.CipherStrength;
#if NET6_0_OR_GREATER
                            result.CipherSuite = ssl.NegotiatedCipherSuite.ToString();
#endif
                            if (ssl.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman) {
                                result.DhKeyBits = ssl.KeyExchangeStrength;
                            }

                            using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                            await secureWriter.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                        } catch (AuthenticationException ex) {
                            logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
                        } finally {
                            result.Protocol = ssl.SslProtocol;
#if NET8_0_OR_GREATER
                            result.SupportsTls13 = result.Protocol == SslProtocols.Tls13;
#else
                            result.SupportsTls13 = (int)result.Protocol == 12288;
#endif
                        }
                    }
                }
            } catch (Exception ex) {
                logger?.WriteError("SMTP TLS check failed for {0}:{1} - {2}", host, port, ex.Message);
            }

            return result;
        }
    }
}