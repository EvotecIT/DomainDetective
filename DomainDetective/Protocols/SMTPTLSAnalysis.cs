using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Threading;

namespace DomainDetective {
    public class SMTPTLSAnalysis {
        public class TlsResult {
            public bool CertificateValid { get; set; }
            public int DaysToExpire { get; set; }
            public List<SslProtocols> SupportedProtocols { get; } = new();
        }

        public Dictionary<string, TlsResult> ServerResults { get; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger) {
            ServerResults.Clear();
            var result = new TlsResult();
            foreach (var protocol in _protocolsToTest) {
                if (await CheckProtocol(host, port, protocol, result, logger)) {
                    result.SupportedProtocols.Add(protocol);
                }
            }
            ServerResults[$"{host}:{port}"] = result;
        }

        private static readonly SslProtocols[] _protocolsToTest = new[] {
            SslProtocols.Tls,
            SslProtocols.Tls11,
            SslProtocols.Tls12,
#if NET8_0_OR_GREATER
            SslProtocols.Tls13,
#endif
        };

        private static async Task<bool> CheckProtocol(string host, int port, SslProtocols protocol, TlsResult result, InternalLogger logger) {
            using var client = new TcpClient();
            try {
                await client.ConnectAsync(host, port);
                using var ssl = new SslStream(client.GetStream(), false, (sender, certificate, chain, errors) => {
                    result.CertificateValid = errors == SslPolicyErrors.None;
                    if (certificate is X509Certificate2 cert) {
                        result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    }
                    return true; // continue even if invalid
                });

                var authTask = ssl.AuthenticateAsClientAsync(host, null, protocol, false);
                if (await Task.WhenAny(authTask, Task.Delay(TimeSpan.FromSeconds(5))) != authTask) {
                    client.Close();
                    logger?.WriteVerbose($"{host}:{port} handshake timed out for {protocol}");
                    return false;
                }
                await authTask; // propagate exceptions
                logger?.WriteVerbose($"{host}:{port} supports {protocol}");
                return true;
            } catch (Exception ex) {
                logger?.WriteVerbose($"{host}:{port} does not support {protocol}: {ex.Message}");
                return false;
            }
        }
    }
}
