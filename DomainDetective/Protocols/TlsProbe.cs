using System;
using System.Collections.Generic;
using DomainDetective.Helpers;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
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
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    public sealed class Result : IDisposable
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
        public string? SanParsingError { get; set; }

        public void Dispose()
        {
            Certificate?.Dispose();
            foreach (var cert in Chain)
            {
                cert.Dispose();
            }
        }
    }

    public static Task<Result> ProbeAsync(string host, int port = 443, CancellationToken token = default)
        => ProbeAsync(host, port, null, token);

    public static async Task<Result> ProbeAsync(string host, int port, TimeSpan? timeout, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentNullException(nameof(host));
        }

        return await ProbeAsyncCore(
            clientFactory: static () => new TcpClient(),
            connectAsync: (client, ct) => ConnectAsync(client, host, port, ct),
            sniHost: host,
            timeout: timeout,
            token: token).ConfigureAwait(false);
    }

    public static Task<Result> ProbeAsync(IPAddress address, string sniHost, int port = 443, CancellationToken token = default)
        => ProbeAsync(address, sniHost, port, null, token);

    public static async Task<Result> ProbeAsync(IPAddress address, string sniHost, int port, TimeSpan? timeout, CancellationToken token)
    {
        if (address == null)
        {
            throw new ArgumentNullException(nameof(address));
        }
        if (string.IsNullOrWhiteSpace(sniHost))
        {
            throw new ArgumentNullException(nameof(sniHost));
        }

        return await ProbeAsyncCore(
            clientFactory: () => new TcpClient(address.AddressFamily),
            connectAsync: (client, ct) => ConnectAsync(client, address, port, ct),
            sniHost: sniHost,
            timeout: timeout,
            token: token).ConfigureAwait(false);
    }

    private static async Task<Result> ProbeAsyncCore(Func<TcpClient> clientFactory, Func<TcpClient, CancellationToken, Task> connectAsync, string sniHost, TimeSpan? timeout, CancellationToken token)
    {
        var result = new Result();
        using var client = clientFactory();
        using var timeoutCts = timeout.HasValue ? CancellationTokenSource.CreateLinkedTokenSource(token) : null;
        if (timeout.HasValue)
        {
            timeoutCts!.CancelAfter(timeout.Value);
        }
        var ct = timeoutCts?.Token ?? token;

        await connectAsync(client, ct).ConfigureAwait(false);

        using var ssl = new SslStream(client.GetStream(), false, (_, certificate, chain, errors) =>
        {
            PopulateFromValidation(result, certificate, chain, errors);
            return true;
        });

        try
        {
            await ssl.AuthenticateAsClientAsync(sniHost).WaitWithCancellation(ct).ConfigureAwait(false);
#if NET8_0_OR_GREATER
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

    private static async Task ConnectAsync(TcpClient client, string host, int port, CancellationToken cancellationToken)
    {
        await client.ConnectAsync(host, port).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ConnectAsync(TcpClient client, IPAddress address, int port, CancellationToken cancellationToken)
    {
        await client.ConnectAsync(address, port).WaitWithCancellation(cancellationToken).ConfigureAwait(false);
    }

    private static void PopulateFromValidation(Result result, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors)
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
            foreach (var s in chain.ChainStatus)
            {
                result.ChainErrors.Add(s.Status);
            }
        }

        if (certificate is not X509Certificate2 cert)
        {
            return;
        }

        result.Certificate?.Dispose();
        result.Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
        result.CertificateSubject = result.Certificate.Subject;
        result.CertificateIssuer = result.Certificate.Issuer;
        result.NotBefore = result.Certificate.NotBefore;
        result.NotAfter = result.Certificate.NotAfter;
        result.DnsNames.Clear();
        result.SanParsingError = null;
        TryAddDnsNames(result);
    }

    private static void TryAddDnsNames(Result result)
    {
        if (result.Certificate == null)
        {
            return;
        }

        try
        {
#if NET8_0_OR_GREATER
            var san = result.Certificate.Extensions[SubjectAlternativeNameOid];
            if (san != null)
            {
                var sanExt = new X509SubjectAlternativeNameExtension(san.RawData, san.Critical);
                foreach (var name in sanExt.EnumerateDnsNames())
                {
                    if (!string.IsNullOrWhiteSpace(name))
                    {
                        result.DnsNames.Add(name);
                    }
                }
            }
#else
            var san = result.Certificate.Extensions[SubjectAlternativeNameOid];
            if (san != null)
            {
                var raw = san.Format(false);
                foreach (var part in raw.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var p = part.Trim();
                    var idx = p.IndexOf('=');
                    if (idx > 0 && p.Substring(0, idx).Trim().Equals("DNS Name", StringComparison.OrdinalIgnoreCase))
                    {
                        var name = p.Substring(idx + 1).Trim();
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            result.DnsNames.Add(name);
                        }
                    }
                }
            }
#endif
        }
        catch (Exception ex) when (!ExceptionHelper.IsFatal(ex))
        {
            result.SanParsingError = ex.Message;
        }
    }
}
