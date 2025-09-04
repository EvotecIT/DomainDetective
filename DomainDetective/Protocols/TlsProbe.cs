using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Lightweight TLS probe to capture negotiated protocol/cipher and certificate summary for a host:port.
/// </summary>
/// <para>Shared by analyses that need basic TLS metadata without duplicating logic.</para>
public static class TlsProbe
{
    public sealed class Result
    {
        public SslProtocols Protocol { get; set; }
        public string? CipherSuite { get; set; }
        public string? KeyExchangeAlgorithm { get; set; }
        public bool CertificateValid { get; set; }
        public bool HostnameMatch { get; set; }
        public bool ChainValid => ChainErrors.Count == 0;
        public List<X509ChainStatusFlags> ChainErrors { get; } = new();
        public List<X509Certificate2> Chain { get; } = new();
        public X509Certificate2? Certificate { get; set; }
        public string? CertificateSubject { get; set; }
        public string? CertificateIssuer { get; set; }
        public DateTime? NotBefore { get; set; }
        public DateTime? NotAfter { get; set; }
        public List<string> DnsNames { get; } = new();
    }

    public static async Task<Result> ProbeAsync(string host, int port = 443, CancellationToken token = default)
    {
        var result = new Result();
        using var client = new TcpClient();
#if NET6_0_OR_GREATER
        await client.ConnectAsync(host, port, token);
#else
        await client.ConnectAsync(host, port).WaitWithCancellation(token);
#endif
        using var ssl = new SslStream(client.GetStream(), false, (sender, certificate, chain, errors) =>
        {
            result.CertificateValid = errors == SslPolicyErrors.None;
            result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
            result.ChainErrors.Clear();
            result.Chain.Clear();
            if (chain != null)
            {
                foreach (var element in chain.ChainElements)
                {
                    result.Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                }
                foreach (var s in chain.ChainStatus) result.ChainErrors.Add(s.Status);
            }
            if (certificate is X509Certificate2 cert)
            {
                result.Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
                result.CertificateSubject = result.Certificate.Subject;
                result.CertificateIssuer = result.Certificate.Issuer;
                result.NotBefore = result.Certificate.NotBefore;
                result.NotAfter = result.Certificate.NotAfter;
                try
                {
                    var san = result.Certificate.Extensions["2.5.29.17"]; // subjectAltName
                    if (san != null)
                    {
                        // very lightweight parse for DNS names
                        var raw = san.Format(false);
                        foreach (var part in raw.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            var p = part.Trim();
                            var idx = p.IndexOf('=');
                            if (idx > 0 && p.Substring(0, idx).Trim().Equals("DNS Name", StringComparison.OrdinalIgnoreCase))
                            {
                                var name = p.Substring(idx + 1).Trim();
                                if (!string.IsNullOrWhiteSpace(name)) result.DnsNames.Add(name);
                            }
                        }
                    }
                }
                catch { }
            }
            return true;
        });
        try
        {
#if NET8_0_OR_GREATER
            await ssl.AuthenticateAsClientAsync(host, null, SslProtocols.Tls13 | SslProtocols.Tls12, false);
#else
            await ssl.AuthenticateAsClientAsync(host);
#endif
#if NET6_0_OR_GREATER
            result.CipherSuite = ssl.NegotiatedCipherSuite.ToString();
#endif
            result.KeyExchangeAlgorithm = ssl.KeyExchangeAlgorithm.ToString();
        }
        finally
        {
            result.Protocol = ssl.SslProtocol;
        }
        return result;
    }
}

