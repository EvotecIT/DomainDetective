using DomainDetective.Helpers;
using DomainDetective.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

/// <summary>FTP TLS negotiation mode.</summary>
public enum FtpTlsMode {
    /// <summary>Connect in clear text and upgrade with the FTP AUTH TLS command.</summary>
    Explicit = 0,
    /// <summary>Start TLS immediately after the TCP connection.</summary>
    Implicit = 1
}

/// <summary>Logical FTP TLS endpoint and optional pinned transport address.</summary>
public sealed class FtpTlsEndpoint {
    /// <summary>Creates an FTP TLS endpoint.</summary>
    public FtpTlsEndpoint(string hostName, int port, FtpTlsMode mode) {
        HostName = EndpointHostNormalizer.Normalize(hostName);
        Port = port;
        Mode = mode;
        Validate();
    }

    /// <summary>Logical hostname used for DNS and TLS SNI.</summary>
    public string HostName { get; }

    /// <summary>TCP port.</summary>
    public int Port { get; }

    /// <summary>TLS negotiation mode.</summary>
    public FtpTlsMode Mode { get; }

    /// <summary>Optional concrete address to connect while retaining <see cref="HostName"/> for SNI.</summary>
    public IPAddress? ConnectAddress { get; set; }

    /// <summary>Validates the endpoint.</summary>
    public void Validate() {
        if (HostName.Length == 0) {
            throw new ArgumentException("An FTP TLS hostname is required.", nameof(HostName));
        }
        if (Port < 1 || Port > 65535) {
            throw new ArgumentOutOfRangeException(nameof(Port), "Port must be between 1 and 65535.");
        }
    }
}

/// <summary>Requested and observed FTP TLS connection evidence.</summary>
public sealed class FtpTlsConnectionEvidence {
    /// <summary>Logical hostname used by FTP and TLS.</summary>
    public string HostName { get; set; } = string.Empty;

    /// <summary>TCP port used by the probe.</summary>
    public int Port { get; set; }

    /// <summary>Concrete caller-selected address, when supplied.</summary>
    public string? ConnectAddress { get; set; }

    /// <summary>Actual remote address reached by the probe.</summary>
    public string? RemoteAddress { get; set; }

    /// <summary>Address family of <see cref="RemoteAddress"/>.</summary>
    public string? RemoteAddressFamily { get; set; }
}

/// <summary>Protocol and certificate evidence returned by an FTP TLS probe.</summary>
public sealed class FtpTlsResult {
    /// <summary>UTC time when this protocol observation completed.</summary>
    public DateTimeOffset ObservedAtUtc { get; set; }

    /// <summary>Requested and observed connection evidence.</summary>
    public FtpTlsConnectionEvidence Connection { get; set; } = new();

    /// <summary>TLS negotiation mode used by the probe.</summary>
    public FtpTlsMode Mode { get; set; }

    /// <summary>FTP greeting lines observed before explicit TLS negotiation.</summary>
    public IReadOnlyList<string> Greeting { get; set; } = Array.Empty<string>();

    /// <summary>FTP response lines returned for AUTH TLS.</summary>
    public IReadOnlyList<string> AuthTlsResponse { get; set; } = Array.Empty<string>();

    /// <summary>True when a TLS session was negotiated.</summary>
    public bool TlsNegotiated { get; set; }

    /// <summary>True when platform certificate validation succeeded.</summary>
    public bool CertificateValid { get; set; }

    /// <summary>True when the certificate matched the logical hostname.</summary>
    public bool HostnameMatch { get; set; }

    /// <summary>TLS policy errors reported by the platform validation callback.</summary>
    public SslPolicyErrors PolicyErrors { get; set; }

    /// <summary>Certificate-chain status flags reported by platform chain validation.</summary>
    public List<X509ChainStatusFlags> ChainErrors { get; } = new();

    /// <summary>True when platform chain validation reported no chain errors.</summary>
    public bool ChainValid => ChainErrors.Count == 0 &&
                              (PolicyErrors & SslPolicyErrors.RemoteCertificateChainErrors) == 0;

    /// <summary>Negotiated TLS protocol.</summary>
    public SslProtocols Protocol { get; set; }

    /// <summary>Leaf certificate captured during negotiation.</summary>
    public X509Certificate2? Certificate { get; set; }

    /// <summary>Certificate chain captured during negotiation.</summary>
    public List<X509Certificate2> Chain { get; } = new();

    /// <summary>Best-effort failure reason.</summary>
    public string? FailureReason { get; set; }

    /// <summary>Normalized failure classification.</summary>
    public CertificateFailureKind FailureKind { get; set; }
}

/// <summary>Performs protocol-correct explicit or implicit FTP TLS certificate probing without authentication.</summary>
public sealed class FtpTlsAnalysis {
    private const int MaxResponseLines = 100;

    /// <summary>Timeout applied to connect, FTP response, and TLS negotiation.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Analyzes one FTP TLS endpoint. The probe never submits user credentials or opens a data connection.</summary>
    public async Task<FtpTlsResult> AnalyzeAsync(
        FtpTlsEndpoint endpoint,
        InternalLogger logger,
        CancellationToken cancellationToken = default) {
        if (endpoint == null) {
            throw new ArgumentNullException(nameof(endpoint));
        }
        endpoint.Validate();
        var result = new FtpTlsResult {
            Mode = endpoint.Mode,
            Connection = new FtpTlsConnectionEvidence {
                HostName = endpoint.HostName,
                Port = endpoint.Port,
                ConnectAddress = endpoint.ConnectAddress?.ToString()
            }
        };

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try {
            using var client = endpoint.ConnectAddress == null
                ? new TcpClient()
                : new TcpClient(endpoint.ConnectAddress.AddressFamily);
            if (endpoint.ConnectAddress == null) {
                await client.ConnectAsync(endpoint.HostName, endpoint.Port)
                    .WaitWithCancellation(timeoutCts.Token)
                    .ConfigureAwait(false);
            } else {
                await client.ConnectAsync(endpoint.ConnectAddress, endpoint.Port)
                    .WaitWithCancellation(timeoutCts.Token)
                    .ConfigureAwait(false);
            }
            CaptureRemoteEndpoint(client, result.Connection);

            using NetworkStream network = client.GetStream();
            if (endpoint.Mode == FtpTlsMode.Explicit) {
                using var reader = new StreamReader(network, Encoding.ASCII, false, 1024, true);
                using var writer = new StreamWriter(network, Encoding.ASCII, 1024, true) {
                    AutoFlush = true,
                    NewLine = "\r\n"
                };
                IReadOnlyList<string> greeting = await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);
                result.Greeting = greeting;
                if (!HasReplyCode(greeting, "220")) {
                    throw new InvalidDataException("FTP server did not return a 220 service-ready greeting.");
                }

                await writer.WriteLineAsync("AUTH TLS").WaitWithCancellation(timeoutCts.Token).ConfigureAwait(false);
                IReadOnlyList<string> authResponse = await ReadResponseAsync(reader, timeoutCts.Token).ConfigureAwait(false);
                result.AuthTlsResponse = authResponse;
                if (!HasReplyCode(authResponse, "234")) {
                    throw new InvalidDataException("FTP server did not accept AUTH TLS with a 234 response.");
                }
            }

            using var ssl = new SslStream(network, false, (sender, certificate, chain, errors) => {
                result.PolicyErrors = errors;
                result.CertificateValid = errors == SslPolicyErrors.None;
                result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                result.Chain.Clear();
                result.ChainErrors.Clear();
                if (certificate != null) {
                    result.Certificate = CertificateLoaderCompat.LoadCertificate(certificate.Export(X509ContentType.Cert));
                }
                if (chain != null) {
                    foreach (X509ChainElement element in chain.ChainElements) {
                        result.Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
                    }
                    foreach (X509ChainStatus status in chain.ChainStatus) {
                        if (status.Status != X509ChainStatusFlags.NoError) {
                            result.ChainErrors.Add(status.Status);
                        }
                    }
                }
                if ((errors & SslPolicyErrors.RemoteCertificateChainErrors) != 0 && result.ChainErrors.Count == 0) {
                    result.ChainErrors.Add(X509ChainStatusFlags.PartialChain);
                }
                return true;
            });
            await ssl.AuthenticateAsClientAsync(endpoint.HostName, null, SslProtocols.None, true)
                .WaitWithCancellation(timeoutCts.Token)
                .ConfigureAwait(false);
            result.Protocol = ssl.SslProtocol;
            result.TlsNegotiated = true;
            return result;
        } catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) {
            var exception = new TimeoutException("The FTP TLS probe timed out.");
            SetFailure(result, exception);
            logger.WriteVerbose("FTP TLS probe timed out for {0}:{1}.", endpoint.HostName, endpoint.Port);
            return result;
        } catch (Exception ex) when (ex is not OperationCanceledException) {
            SetFailure(result, ex);
            logger.WriteVerbose("FTP TLS probe failed for {0}:{1}: {2}", endpoint.HostName, endpoint.Port, ex.Message);
            return result;
        } finally {
            result.ObservedAtUtc = DateTimeOffset.UtcNow;
        }
    }

    private static async Task<IReadOnlyList<string>> ReadResponseAsync(
        StreamReader reader,
        CancellationToken cancellationToken) {
        var lines = new List<string>();
        string? first = await reader.ReadLineAsync().WaitWithCancellation(cancellationToken).ConfigureAwait(false);
        if (first == null) {
            throw new EndOfStreamException("FTP server closed the connection before returning a response.");
        }
        lines.Add(first);
        if (first.Length < 4 || first[3] != '-' || !IsReplyCode(first.Substring(0, 3))) {
            return lines;
        }

        string terminator = first.Substring(0, 3) + " ";
        while (lines.Count < MaxResponseLines) {
            string? line = await reader.ReadLineAsync().WaitWithCancellation(cancellationToken).ConfigureAwait(false);
            if (line == null) {
                throw new EndOfStreamException("FTP server closed a multiline response before its terminator.");
            }
            lines.Add(line);
            if (line.StartsWith(terminator, StringComparison.Ordinal)) {
                return lines;
            }
        }
        throw new InvalidDataException($"FTP response exceeded {MaxResponseLines} lines.");
    }

    private static bool HasReplyCode(IReadOnlyList<string> response, string expected) {
        if (response.Count == 0) {
            return false;
        }
        string finalLine = response[response.Count - 1];
        return string.Equals(finalLine, expected, StringComparison.Ordinal) ||
               finalLine.StartsWith(expected + " ", StringComparison.Ordinal);
    }

    private static bool IsReplyCode(string value) {
        return value.Length == 3 && char.IsDigit(value[0]) && char.IsDigit(value[1]) && char.IsDigit(value[2]);
    }

    private static void CaptureRemoteEndpoint(TcpClient client, FtpTlsConnectionEvidence connection) {
        if (client.Client.RemoteEndPoint is IPEndPoint endpoint) {
            IPAddress address = endpoint.Address.IsIPv4MappedToIPv6 ? endpoint.Address.MapToIPv4() : endpoint.Address;
            connection.RemoteAddress = address.ToString();
            connection.RemoteAddressFamily = IpAddressClassifier.GetAddressFamilyLabel(address);
        }
    }

    private static void SetFailure(FtpTlsResult result, Exception exception) {
        result.FailureReason = CertificateAnalysis.BuildFailureReason(exception);
        result.FailureKind = CertificateFailureClassifier.Classify(exception);
    }
}
