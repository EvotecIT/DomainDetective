using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>
/// Provides TLS analysis for various mail protocols.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class MailTlsAnalysis
{
    /// <summary>Supported mail protocols.</summary>
    public enum MailProtocol
    {
        Smtp,
        Imap,
        Pop3
    }

    /// <summary>Result of a TLS check.</summary>
    public class TlsResult
    {
        public bool StartTlsAdvertised { get; set; }
        public bool CertificateValid { get; set; }
        public int DaysToExpire { get; set; }
        public SslProtocols Protocol { get; set; }
        public bool SupportsTls13 { get; set; }
        public bool Tls13Used { get; set; }
        public bool HostnameMatch { get; set; }
        public CipherAlgorithmType CipherAlgorithm { get; set; }
        public int CipherStrength { get; set; }
        public string CipherSuite { get; set; } = string.Empty;
        public int DhKeyBits { get; set; }
        public List<X509Certificate2> Chain { get; } = new();
        public List<X509ChainStatusFlags> ChainErrors { get; } = new();
    }

    /// <summary>Stores results for each server.</summary>
    public Dictionary<string, TlsResult> ServerResults { get; } = new();
    /// <summary>Timeout for connections.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Analyzes a single host.</summary>
    public async Task AnalyzeServer(MailProtocol protocol, string host, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        var result = await CheckTls(protocol, host, port, logger, cancellationToken);
        ServerResults[$"{host}:{port}"] = result;
    }

    /// <summary>Analyzes multiple hosts.</summary>
    public async Task AnalyzeServers(MailProtocol protocol, IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default)
    {
        ServerResults.Clear();
        foreach (var host in hosts)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ServerResults[$"{host}:{port}"] = await CheckTls(protocol, host, port, logger, cancellationToken);
        }
    }

    private static string GetQuitCommand(MailProtocol protocol) => protocol switch
    {
        MailProtocol.Imap => "A3 LOGOUT",
        _ => "QUIT"
    };

    private async Task<TlsResult> CheckTls(MailProtocol protocol, string host, int port, InternalLogger logger, CancellationToken cancellationToken)
    {
        var result = new TlsResult();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try
        {
            using var client = new TcpClient();
#if NET6_0_OR_GREATER
            await client.ConnectAsync(host, port, timeoutCts.Token);
#else
            await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
#endif
            using NetworkStream network = client.GetStream();
            bool directTls = (protocol == MailProtocol.Imap && port == 993) || (protocol == MailProtocol.Pop3 && port == 995);
            if (directTls)
            {
                using var ssl = new SslStream(network, false, (sender, certificate, chain, errors) =>
                {
                    result.CertificateValid = errors == SslPolicyErrors.None;
                    result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                    result.Chain.Clear();
                    result.ChainErrors.Clear();
                    if (certificate is X509Certificate2 cert)
                    {
                        result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                        if (chain != null)
                        {
                            foreach (var element in chain.ChainElements)
                            {
                                result.Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                            }
                            foreach (var status in chain.ChainStatus)
                            {
                                result.ChainErrors.Add(status.Status);
                            }
                        }
                    }
                    return true;
                });
                try
                {
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
                    if (ssl.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman)
                    {
                        result.DhKeyBits = ssl.KeyExchangeStrength;
                    }
                    using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                    await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                }
                catch (AuthenticationException ex)
                {
                    logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
                }
                finally
                {
                    result.Protocol = ssl.SslProtocol;
#if NET8_0_OR_GREATER
                    result.SupportsTls13 = result.Protocol == SslProtocols.Tls13;
                    result.Tls13Used = result.SupportsTls13;
#else
                    result.SupportsTls13 = (int)result.Protocol == 12288;
                    result.Tls13Used = result.SupportsTls13;
#endif
                    result.StartTlsAdvertised = true;
                }
                return result;
            }

            using var reader = new StreamReader(network);
            using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };
#if NET8_0_OR_GREATER
            await reader.ReadLineAsync(timeoutCts.Token);
#else
            await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
#endif
            timeoutCts.Token.ThrowIfCancellationRequested();
            var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            switch (protocol)
            {
                case MailProtocol.Smtp:
                    await writer.WriteLineAsync("EHLO example.com");
                    string line;
                    while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null)
                    {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger?.WriteVerbose($"EHLO response: {line}");
                        if (line.StartsWith("250"))
                        {
                            string capLine = line.Substring(4).Trim();
                            foreach (var part in capLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries))
                            {
                                capabilities.Add(part);
                            }
                            if (!line.StartsWith("250-"))
                            {
                                break;
                            }
                        }
                        else if (line.StartsWith("4") || line.StartsWith("5"))
                        {
                            break;
                        }
                    }
                    result.StartTlsAdvertised = capabilities.Contains("STARTTLS");
                    break;
                case MailProtocol.Imap:
                    await writer.WriteLineAsync("A1 CAPABILITY");
                    while (true)
                    {
                        var resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        if (resp == null)
                        {
                            break;
                        }
                        logger?.WriteVerbose($"CAPABILITY response: {resp}");
                        if (resp.StartsWith("*"))
                        {
                            var capLine = resp.Substring(1).Trim();
                            if (capLine.StartsWith("CAPABILITY", StringComparison.OrdinalIgnoreCase))
                            {
                                var caps = capLine.Substring(10).Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                foreach (var cap in caps)
                                {
                                    capabilities.Add(cap);
                                }
                            }
                        }
                        else if (resp.StartsWith("A1", StringComparison.OrdinalIgnoreCase))
                        {
                            break;
                        }
                    }
                    result.StartTlsAdvertised = capabilities.Contains("STARTTLS");
                    break;
                case MailProtocol.Pop3:
                    await writer.WriteLineAsync("CAPA");
                    string popLine;
                    while ((popLine = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null)
                    {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger?.WriteVerbose($"CAPA response: {popLine}");
                        if (popLine == ".")
                        {
                            break;
                        }
                        capabilities.Add(popLine.Trim());
                    }
                    result.StartTlsAdvertised = capabilities.Contains("STLS");
                    if (!result.StartTlsAdvertised)
                    {
                        await writer.WriteLineAsync("STLS").WaitWithCancellation(timeoutCts.Token);
                        var resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                        if (resp != null && resp.StartsWith("+OK"))
                        {
                            result.StartTlsAdvertised = true;
                        }
                        else
                        {
                            await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                            await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                            await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                            return result;
                        }
                    }
                    break;
            }

            if (!result.StartTlsAdvertised)
            {
                await writer.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                return result;
            }

            var startTlsCommand = protocol switch
            {
                MailProtocol.Smtp => "STARTTLS",
                MailProtocol.Imap => "A2 STARTTLS",
                MailProtocol.Pop3 => "STLS",
                _ => "STARTTLS"
            };
            await writer.WriteLineAsync(startTlsCommand).WaitWithCancellation(timeoutCts.Token);
            var startTlsResp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
            bool proceed = protocol switch
            {
                MailProtocol.Smtp => startTlsResp != null && startTlsResp.StartsWith("220"),
                MailProtocol.Imap => startTlsResp != null && startTlsResp.StartsWith("A2", StringComparison.OrdinalIgnoreCase) && startTlsResp.Contains("OK", StringComparison.OrdinalIgnoreCase),
                MailProtocol.Pop3 => startTlsResp != null && startTlsResp.StartsWith("+OK"),
                _ => false
            };
            if (!proceed)
            {
                logger?.WriteVerbose($"{host}:{port} STARTTLS rejected: {startTlsResp}");
                return result;
            }

            using var sslStream = new SslStream(network, false, (sender, certificate, chain, errors) =>
            {
                result.CertificateValid = errors == SslPolicyErrors.None;
                result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                result.Chain.Clear();
                result.ChainErrors.Clear();
                if (certificate is X509Certificate2 cert)
                {
                    result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    if (chain != null)
                    {
                        foreach (var element in chain.ChainElements)
                        {
                            result.Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                        }
                        foreach (var status in chain.ChainStatus)
                        {
                            result.ChainErrors.Add(status.Status);
                        }
                    }
                }
                return true;
            });

            try
            {
#if NET8_0_OR_GREATER
                await sslStream.AuthenticateAsClientAsync(host, null, SslProtocols.Tls13 | SslProtocols.Tls12, false)
                    .WaitWithCancellation(timeoutCts.Token);
#else
                await sslStream.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
#endif
                result.CipherAlgorithm = sslStream.CipherAlgorithm;
                result.CipherStrength = sslStream.CipherStrength;
#if NET6_0_OR_GREATER
                result.CipherSuite = sslStream.NegotiatedCipherSuite.ToString();
#endif
                if (sslStream.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman)
                {
                    result.DhKeyBits = sslStream.KeyExchangeStrength;
                }
                using var secureWriter = new StreamWriter(sslStream) { AutoFlush = true, NewLine = "\r\n" };
                await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
            }
            catch (AuthenticationException ex)
            {
                logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
            }
            finally
            {
                result.Protocol = sslStream.SslProtocol;
#if NET8_0_OR_GREATER
                result.SupportsTls13 = result.Protocol == SslProtocols.Tls13;
                result.Tls13Used = result.SupportsTls13;
#else
                result.SupportsTls13 = (int)result.Protocol == 12288;
                result.Tls13Used = result.SupportsTls13;
#endif
            }
        }
        catch (Exception ex)
        {
            logger?.WriteError("TLS check failed for {0}:{1} - {2}", host, port, ex.Message);
        }

        return result;
    }
}
