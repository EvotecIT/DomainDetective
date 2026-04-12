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

    /// <summary>Provides result functionality.</summary>
    public sealed class Result : IDisposable
    {
        /// <summary>Negotiated TLS protocol, or <see cref="SslProtocols.None"/> when authentication did not complete.</summary>
        public SslProtocols Protocol { get; set; }
        /// <summary>Gets or sets the cipher suite value.</summary>
        public string? CipherSuite { get; set; }
        /// <summary>Gets or sets the key exchange algorithm value.</summary>
        public string? KeyExchangeAlgorithm { get; set; }
        /// <summary>Gets or sets the certificate valid value.</summary>
        public bool CertificateValid { get; set; }
        /// <summary>Gets or sets the hostname match value.</summary>
        public bool HostnameMatch { get; set; }
        /// <summary>Represents the chain valid value.</summary>
        public bool ChainValid => ChainErrors.Count == 0;
        /// <summary>Gets the chain errors value.</summary>
        public List<X509ChainStatusFlags> ChainErrors { get; } = new();
        /// <summary>Gets the chain value.</summary>
        public List<X509Certificate2> Chain { get; } = new();
        /// <summary>Gets or sets the certificate value.</summary>
        public X509Certificate2? Certificate { get; set; }
        /// <summary>Gets or sets the certificate subject value.</summary>
        public string? CertificateSubject { get; set; }
        /// <summary>Gets or sets the certificate issuer value.</summary>
        public string? CertificateIssuer { get; set; }
        /// <summary>Gets or sets the not before value.</summary>
        public DateTime? NotBefore { get; set; }
        /// <summary>Gets or sets the not after value.</summary>
        public DateTime? NotAfter { get; set; }
        /// <summary>Remote endpoint IP address captured after a successful TCP connection.</summary>
        /// <remarks>Captured together with <see cref="RemotePort"/> and kept flat for serialization callers.</remarks>
        public IPAddress? RemoteAddress { get; set; }
        /// <summary>Remote endpoint port captured after a successful TCP connection.</summary>
        /// <remarks>Captured together with <see cref="RemoteAddress"/> and kept flat for serialization callers.</remarks>
        public int? RemotePort { get; set; }
        /// <summary>Gets the dns names value.</summary>
        public List<string> DnsNames { get; } = new();
        /// <summary>Gets or sets the san parsing error value.</summary>
        public string? SanParsingError { get; set; }

        /// <summary>Executes the dispose operation.</summary>
        public void Dispose()
        {
            Certificate?.Dispose();
            foreach (var cert in Chain)
            {
                cert.Dispose();
            }
        }
    }

    /// <summary>
    /// Represents a TLS probe failure with endpoint evidence captured before the failure.
    /// </summary>
    public sealed class TlsProbeException : Exception
    {
        /// <summary>Remote endpoint IP address captured after a successful TCP connection.</summary>
        public IPAddress? RemoteAddress { get; }

        /// <summary>Remote endpoint port captured after a successful TCP connection.</summary>
        public int? RemotePort { get; }

        /// <summary>Initializes a new instance of the <see cref="TlsProbeException"/> class.</summary>
        public TlsProbeException(string message, Exception innerException, IPAddress? remoteAddress, int? remotePort)
            : base(message, innerException)
        {
            RemoteAddress = remoteAddress;
            RemotePort = remotePort;
        }
    }

    /// <summary>Executes the probe async operation.</summary>
    public static Task<Result> ProbeAsync(string host, int port = 443, CancellationToken token = default)
        => ProbeAsync(host, port, null, token);

    /// <summary>Executes the probe async operation.</summary>
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

    /// <summary>
    /// Executes the probe async operation and wraps TLS-stage failures with endpoint evidence when available.
    /// </summary>
    public static Task<Result> ProbeWithFailureEvidenceAsync(string host, int port = 443, CancellationToken token = default)
        => ProbeWithFailureEvidenceAsync(host, port, null, token);

    /// <summary>
    /// Executes the probe async operation and wraps TLS-stage failures with endpoint evidence when available.
    /// </summary>
    public static async Task<Result> ProbeWithFailureEvidenceAsync(string host, int port, TimeSpan? timeout, CancellationToken token)
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
            token: token,
            includeFailureEvidence: true).ConfigureAwait(false);
    }

    /// <summary>Executes the probe async operation.</summary>
    public static Task<Result> ProbeAsync(IPAddress address, string sniHost, int port = 443, CancellationToken token = default)
        => ProbeAsync(address, sniHost, port, null, token);

    /// <summary>Executes the probe async operation.</summary>
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

    /// <summary>
    /// Executes the probe async operation and wraps TLS-stage failures with endpoint evidence when available.
    /// </summary>
    public static Task<Result> ProbeWithFailureEvidenceAsync(IPAddress address, string sniHost, int port = 443, CancellationToken token = default)
        => ProbeWithFailureEvidenceAsync(address, sniHost, port, null, token);

    /// <summary>
    /// Executes the probe async operation and wraps TLS-stage failures with endpoint evidence when available.
    /// </summary>
    public static async Task<Result> ProbeWithFailureEvidenceAsync(IPAddress address, string sniHost, int port, TimeSpan? timeout, CancellationToken token)
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
            token: token,
            includeFailureEvidence: true).ConfigureAwait(false);
    }

    internal static async Task<Result> ProbeAsyncCore(Func<TcpClient> clientFactory, Func<TcpClient, CancellationToken, Task> connectAsync, string sniHost, TimeSpan? timeout, CancellationToken token, bool includeFailureEvidence = false)
    {
        var result = new Result();
        using var client = clientFactory();
        using var timeoutCts = timeout.HasValue ? CancellationTokenSource.CreateLinkedTokenSource(token) : null;
        if (timeout.HasValue)
        {
            timeoutCts!.CancelAfter(timeout.Value);
        }
        var ct = timeoutCts?.Token ?? token;

        try
        {
            await connectAsync(client, ct).ConfigureAwait(false);
            if (client.Client.RemoteEndPoint is IPEndPoint remoteEndPoint)
            {
                result.RemoteAddress = remoteEndPoint.Address;
                result.RemotePort = remoteEndPoint.Port;
            }
        }
        catch (Exception ex)
        {
            Exception normalized = NormalizeProbeException(ex, token, timeoutCts);
            if (includeFailureEvidence && result.RemoteAddress != null)
            {
                throw new TlsProbeException(normalized.Message, normalized, result.RemoteAddress, result.RemotePort);
            }

            throw normalized;
        }

        using var ssl = new SslStream(client.GetStream(), false, (_, certificate, chain, errors) =>
        {
            PopulateFromValidation(result, certificate, chain, errors);
            return true;
        });

        try
        {
            await ssl.AuthenticateAsClientAsync(sniHost).WaitWithCancellation(ct).ConfigureAwait(false);
            var tlsInfo = TlsNegotiationInfoFactory.Create(ssl);
            result.CipherSuite = tlsInfo.CipherSuite;
            result.KeyExchangeAlgorithm = tlsInfo.KeyExchangeAlgorithm;
        }
        catch (Exception ex)
        {
            Exception normalized = NormalizeProbeException(ex, token, timeoutCts);
            if (includeFailureEvidence && result.RemoteAddress != null)
            {
                throw new TlsProbeException(normalized.Message, normalized, result.RemoteAddress, result.RemotePort);
            }

            throw normalized;
        }
        finally
        {
            if (ssl.IsAuthenticated)
            {
                result.Protocol = ssl.SslProtocol;
            }
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

    internal static Exception NormalizeProbeException(
        Exception exception,
        CancellationToken callerCancellationToken,
        CancellationTokenSource? probeTimeoutSource = null)
    {
        if (exception == null)
        {
            throw new ArgumentNullException(nameof(exception));
        }

        if (callerCancellationToken.IsCancellationRequested)
        {
            return exception;
        }

        bool timeoutTriggered = probeTimeoutSource?.IsCancellationRequested == true;
        if (!timeoutTriggered &&
            exception is not TaskCanceledException &&
            exception is not OperationCanceledException)
        {
            return exception;
        }

        if (timeoutTriggered ||
            exception is TaskCanceledException ||
            exception is OperationCanceledException)
        {
            return new TimeoutException("The request timed out.", exception);
        }

        return exception;
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
                result.Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
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
        result.Certificate = CertificateLoaderCompat.Clone(cert);
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
