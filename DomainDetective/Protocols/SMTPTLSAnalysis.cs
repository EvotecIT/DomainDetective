using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective {
    public class SMTPTLSAnalysis {
        public class TlsResult {
            public bool CertificateValid { get; set; }
            public int DaysToExpire { get; set; }
            public List<SslProtocols> SupportedProtocols { get; } = new();
        }

        public Dictionary<string, TlsResult> ServerResults { get; } = new();

        public async Task AnalyzeServer(string host, int port, InternalLogger logger) {
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
            try {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port);
                using var ssl = new SslStream(client.GetStream(), false, (sender, certificate, chain, errors) => {
                    result.CertificateValid = errors == SslPolicyErrors.None;
                    if (certificate is X509Certificate2 cert) {
                        result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    }
                    return true; // continue even if invalid
                });

                await ssl.AuthenticateAsClientAsync(host, null, protocol, false);
                logger?.WriteVerbose($"{host}:{port} supports {protocol}");
                return true;
            } catch (Exception ex) {
                logger?.WriteVerbose($"{host}:{port} does not support {protocol}: {ex.Message}");
                return false;
            }
        }
    }
}
