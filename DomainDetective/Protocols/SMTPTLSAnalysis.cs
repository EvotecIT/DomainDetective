using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Threading;

namespace DomainDetective {
    public class SMTPTLSAnalysis {
        public class TlsResult {
            public bool StartTlsAdvertised { get; set; }
            public bool CertificateValid { get; set; }
            public int DaysToExpire { get; set; }
            public SslProtocols Protocol { get; set; }
            public CipherAlgorithmType CipherAlgorithm { get; set; }
            public int CipherStrength { get; set; }
        }

        public Dictionary<string, TlsResult> ServerResults { get; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            var result = await CheckTls(host, port, logger, cancellationToken);
            ServerResults[$"{host}:{port}"] = result;
        }

        public async Task AnalyzeServers(IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            ServerResults.Clear();
            foreach (var host in hosts) {
                cancellationToken.ThrowIfCancellationRequested();
                ServerResults[$"{host}:{port}"] = await CheckTls(host, port, logger, cancellationToken);
            }
        }

        private static async Task<TlsResult> CheckTls(string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
            var result = new TlsResult();
            try {
                using (var client = new TcpClient()) {
                    await client.ConnectAsync(host, port);

                    using NetworkStream network = client.GetStream();
                    using (var reader = new StreamReader(network))
                    using (var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" }) {
                        await reader.ReadLineAsync();
                        cancellationToken.ThrowIfCancellationRequested();
                        await writer.WriteLineAsync($"EHLO example.com");

                        var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        string line;
                        while ((line = await reader.ReadLineAsync()) != null) {
                            cancellationToken.ThrowIfCancellationRequested();
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
                            await writer.WriteLineAsync("QUIT");
                            await writer.FlushAsync();
                            await reader.ReadLineAsync();
                            return result;
                        }

                        await writer.WriteLineAsync("STARTTLS");
                        string resp = await reader.ReadLineAsync();
                        if (resp == null || !resp.StartsWith("220")) {
                            logger?.WriteVerbose($"{host}:{port} STARTTLS rejected: {resp}");
                            return result;
                        }

                        using var ssl = new SslStream(network, false, (sender, certificate, chain, errors) => {
                            result.CertificateValid = errors == SslPolicyErrors.None;
                            if (certificate is X509Certificate2 cert) {
                                result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                            }
                            return true;
                        });

                        await ssl.AuthenticateAsClientAsync(host);
                        result.Protocol = ssl.SslProtocol;
                        result.CipherAlgorithm = ssl.CipherAlgorithm;
                        result.CipherStrength = ssl.CipherStrength;

                        using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                        await secureWriter.WriteLineAsync("QUIT");
                    }
                }
            } catch (Exception ex) {
                logger?.WriteError("SMTP TLS check failed for {0}:{1} - {2}", host, port, ex.Message);
            }

            return result;
        }
    }
}
