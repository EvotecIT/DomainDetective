using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;

namespace DomainDetective;

/// <summary>
/// Provides TLS analysis for various mail protocols.
/// </summary>
/// <para>Part of the DomainDetective project.</para>
public class MailTlsAnalysis : IHasAssessments {
    /// <summary>Gets or sets the subject value.</summary>
    public string? Subject { get; set; }
    /// <summary>Supported mail protocols.</summary>
    public enum MailProtocol {
        /// <summary>Provides tls result functionality.</summary>
        Smtp,
        /// <summary>Provides tls result functionality.</summary>
        Imap,
        /// <summary>Provides tls result functionality.</summary>
        Pop3
    }

    /// <summary>Result of a TLS check.</summary>
    public class TlsResult {
        /// <summary>Gets or sets the start tls advertised value.</summary>
        public bool StartTlsAdvertised { get; set; }
        /// <summary>Gets or sets the certificate valid value.</summary>
        public bool CertificateValid { get; set; }
        /// <summary>Gets or sets the days to expire value.</summary>
        public int DaysToExpire { get; set; }
        /// <summary>Gets or sets the days valid value.</summary>
        public int DaysValid { get; set; }
        /// <summary>Gets or sets the is expired value.</summary>
        public bool IsExpired { get; set; }
        /// <summary>Gets or sets the protocol value.</summary>
        public SslProtocols Protocol { get; set; }
        /// <summary>Gets or sets the supports tls13 value.</summary>
        public bool SupportsTls13 { get; set; }
        /// <summary>Gets or sets the supports tls12 value.</summary>
        public bool SupportsTls12 { get; set; }
        /// <summary>Gets or sets the supports tls11 value.</summary>
        public bool SupportsTls11 { get; set; }
        /// <summary>Gets or sets the supports tls10 value.</summary>
        public bool SupportsTls10 { get; set; }
        /// <summary>Gets or sets the tls13 used value.</summary>
        public bool Tls13Used { get; set; }
        /// <summary>Gets or sets the hostname match value.</summary>
        public bool HostnameMatch { get; set; }
        /// <summary>Gets or sets the cipher algorithm value.</summary>
        public string CipherAlgorithm { get; set; } = string.Empty;
        /// <summary>Gets or sets the cipher strength value.</summary>
        public int CipherStrength { get; set; }
        /// <summary>Gets or sets the cipher suite value.</summary>
        public string CipherSuite { get; set; } = string.Empty;
        /// <summary>Gets or sets the dh key bits value.</summary>
        public int DhKeyBits { get; set; }
        /// <summary>Gets or sets the key exchange algorithm value.</summary>
        public string? KeyExchangeAlgorithm { get; set; }
        /// <summary>Gets or sets the certificate value.</summary>
        public X509Certificate2? Certificate { get; set; }
        /// <summary>Gets the chain value.</summary>
        public List<X509Certificate2> Chain { get; } = new();
        /// <summary>Gets the chain errors value.</summary>
        public List<X509ChainStatusFlags> ChainErrors { get; } = new();
        /// <summary>Represents the chain valid value.</summary>
        public bool ChainValid => ChainErrors.Count == 0;

        // Flattened certificate fields for easier consumption
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
        /// <summary>Gets or sets the certificate serial number value.</summary>
        public string? CertificateSerialNumber { get; set; }
        /// <summary>Gets or sets the certificate signature algorithm value.</summary>
        public string? CertificateSignatureAlgorithm { get; set; }
        /// <summary>Gets or sets the public key algorithm value.</summary>
        public string? PublicKeyAlgorithm { get; set; }
        /// <summary>Gets or sets the public key size value.</summary>
        public int? PublicKeySize { get; set; }
        /// <summary>Gets the certificate dns names value.</summary>
        public List<string> CertificateDnsNames { get; } = new();
        /// <summary>Gets or sets the grade level value.</summary>
        public GradeLevel GradeLevel { get; set; } = GradeLevel.Unknown;
        /// <summary>Gets or sets the legacy enabled value.</summary>
        public bool LegacyEnabled { get; set; }
        /// <summary>Gets or sets the ocsp stapling present value.</summary>
        public bool? OcspStaplingPresent { get; set; }
        /// <summary>Gets or sets the failure reason value.</summary>
        public string? FailureReason { get; set; }
        /// <summary>Gets or sets the failure kind value.</summary>
        public CertificateFailureKind FailureKind { get; set; }
    }

    /// <summary>Stores results for each server.</summary>
    public Dictionary<string, TlsResult> ServerResults { get; } = new();
    /// <summary>Timeout for connections.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Structured assessments captured during mail TLS checks.</summary>
    public List<Assessment> Assessments { get; } = new();
    /// <summary>Represents the recommendations value.</summary>
    public IReadOnlyList<RecommendationAdvice> Recommendations => RecommendationEngine.From(Assessments);

    /// <summary>Analyzes a single host.</summary>
    public async Task AnalyzeServer(MailProtocol protocol, string host, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
        ServerResults.Clear();
        var result = await CheckTls(protocol, host, port, logger, cancellationToken);
        ServerResults[$"{host}:{port}"] = result;
    }

    /// <summary>Analyzes multiple hosts.</summary>
    public async Task AnalyzeServers(MailProtocol protocol, IEnumerable<string> hosts, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
        ServerResults.Clear();
        foreach (var host in hosts) {
            cancellationToken.ThrowIfCancellationRequested();
            ServerResults[$"{host}:{port}"] = await CheckTls(protocol, host, port, logger, cancellationToken);
        }
    }

    private static string GetQuitCommand(MailProtocol protocol) => protocol switch {
        MailProtocol.Imap => "A3 LOGOUT",
        _ => "QUIT"
    };

    private static void PopulateNegotiatedTlsDetails(TlsResult result, SslStream ssl)
    {
        var tlsInfo = TlsNegotiationInfoFactory.Create(ssl);
        result.CipherAlgorithm = tlsInfo.CipherAlgorithm;
        result.CipherStrength = tlsInfo.CipherStrength;
        result.CipherSuite = tlsInfo.CipherSuite;
        result.DhKeyBits = tlsInfo.DhKeyBits;
        result.KeyExchangeAlgorithm = tlsInfo.KeyExchangeAlgorithm;
    }

    private async Task<TlsResult> CheckTls(MailProtocol protocol, string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
        string category = protocol switch { MailProtocol.Smtp => "SMTPTLS", MailProtocol.Imap => "IMAPTLS", MailProtocol.Pop3 => "POP3TLS", _ => "MAILTLS" };
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: category, target: $"{host}:{port}");
        var result = new TlsResult();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try {
            using var client = new TcpClient();
#if NET8_0_OR_GREATER
            await client.ConnectAsync(host, port, timeoutCts.Token);
#else
            await client.ConnectAsync(host, port).WaitWithCancellation(timeoutCts.Token);
#endif
            using NetworkStream network = client.GetStream();
            bool directTls = (protocol == MailProtocol.Imap && port == 993) || (protocol == MailProtocol.Pop3 && port == 995);
            if (directTls) {
                using var ssl = new SslStream(network, false, (sender, certificate, chain, errors) => {
                    result.CertificateValid = errors == SslPolicyErrors.None;
                    result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                    result.Chain.Clear();
                    result.ChainErrors.Clear();
                    if (certificate is X509Certificate2 cert) {
                        result.Certificate = CertificateLoaderCompat.Clone(cert);
                        result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                        result.DaysValid = (int)(cert.NotAfter - cert.NotBefore).TotalDays;
                        result.IsExpired = cert.NotAfter < DateTime.Now;
                        result.CertificateSubject = cert.Subject;
                        result.CertificateIssuer = cert.Issuer;
                        result.CertificateNotBefore = cert.NotBefore;
                        result.CertificateNotAfter = cert.NotAfter;
                        result.CertificateThumbprint = cert.Thumbprint;
                        result.CertificateSerialNumber = cert.SerialNumber;
                        result.CertificateSignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                        try {
                            result.PublicKeyAlgorithm = cert.PublicKey?.Oid?.FriendlyName;
                            // Prefer modern APIs over obsolete PublicKey.Key
                            int? size = null;
                            try { using var rsa = cert.GetRSAPublicKey(); if (rsa != null) size = rsa.KeySize; } catch { }
                            if (!size.HasValue) { try { using var ecdsa = cert.GetECDsaPublicKey(); if (ecdsa != null) size = ecdsa.KeySize; } catch { } }
                            if (!size.HasValue) { try { using var dsa = cert.GetDSAPublicKey(); if (dsa != null) size = dsa.KeySize; } catch { } }
                            result.PublicKeySize = size;
                        } catch { }
                        try {
                            foreach (var ext in cert.Extensions) {
                                if (ext.Oid?.Value == "2.5.29.17") // Subject Alternative Name
                                {
                                    var asn = new System.Security.Cryptography.AsnEncodedData(ext.Oid, ext.RawData);
                                    // Basic parser for DNS names in SAN
                                    var text = asn.Format(true);
                                    foreach (var line in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
                                        var idx = line.IndexOf("DNS Name=", StringComparison.OrdinalIgnoreCase);
                                        if (idx >= 0) {
                                            var name = line.Substring(idx + 9).Trim();
                                            if (!string.IsNullOrWhiteSpace(name)) result.CertificateDnsNames.Add(name);
                                        }
                                    }
                                }
                            }
                        } catch { }
                        if (chain != null) {
                            foreach (var element in chain.ChainElements) {
                                result.Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
                            }
                            foreach (var status in chain.ChainStatus) {
                                result.ChainErrors.Add(status.Status);
                            }
                        }
                    }
                    return true;
                });
                try {
                    await ssl.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
                    PopulateNegotiatedTlsDetails(result, ssl);
                    try {
                        var suite = result.CipherSuite ?? string.Empty;
                        if (!string.IsNullOrEmpty(suite)) {
                            var s = suite.ToUpperInvariant();
                            bool weak = s.Contains("3DES") || s.Contains("RC4") || s.Contains("_CBC_");
                            if (s.Contains("_SHA") && !s.Contains("SHA256") && !s.Contains("SHA384") && !s.Contains("SHA512")) weak = true;
                            if (weak) {
                                logger.WriteWarningCode(TlsCodes.WeakCipherNegotiated, "Weak cipher negotiated on {0}:{1}: {2}", host, port, suite);
                            } else {
                                logger.WriteInformationCode(MailTlsCodes.StrongCipherSuite, "Strong cipher negotiated on {0}:{1}: {2}", host, port, suite);
                            }
                        }
                        if (result.DhKeyBits > 0 && result.DhKeyBits < 2048) {
                            logger.WriteWarningCode(TlsCodes.WeakKeyExchange, "Weak DH key size {0} bits negotiated on {1}:{2}", result.DhKeyBits, host, port);
                        }
                    } catch { }
                    try {
                        using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                        await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                    } catch (ObjectDisposedException) {
                        // Remote closed immediately after handshake; safe to ignore.
                        logger.WriteVerbose($"TLS session closed before QUIT on {host}:{port} (direct TLS)");
                    } catch (IOException ioex) {
                        // Socket closed/reset while attempting QUIT; treat as benign post-handshake.
                        logger.WriteVerbose($"TLS write failed (QUIT) on {host}:{port} - {ioex.Message}");
                    }
                    if (result.CertificateValid && result.ChainValid && result.HostnameMatch && !result.IsExpired) {
                        logger.WriteInformationCode(MailTlsCodes.CertificateValid, "Valid certificate on {0}:{1}", host, port);
                    }
                } catch (AuthenticationException ex) {
                    SetFailure(result, ex);
                    logger.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
                } catch (ObjectDisposedException odex) {
                    SetFailure(result, odex);
                    // Some servers tear down the stream aggressively; report as verbose and continue.
                    logger.WriteVerbose($"TLS stream disposed during operation on {host}:{port} - {odex.Message}");
                } catch (IOException ioex) {
                    SetFailure(result, ioex);
                    logger.WriteVerbose($"TLS I/O error on {host}:{port} - {ioex.Message}");
                } finally {
                    try { result.Protocol = ssl.SslProtocol; } catch (ObjectDisposedException) { result.Protocol = SslProtocols.None; }
                    result.SupportsTls13 = (int)result.Protocol == 12288;
                    result.Tls13Used = result.SupportsTls13;
                    // Probe protocol support (best-effort)
                    await ProbeProtocolSupport(host, port, result, cancellationToken);
                    if (result.SupportsTls10 || result.SupportsTls11) {   
                        logger.WriteWarningCode(TlsCodes.LegacyOffered, "Server offers legacy TLS ({0}{1}) on {2}:{3}",
                            result.SupportsTls10 ? "1.0" : string.Empty,
                            result.SupportsTls11 ? (result.SupportsTls10 ? "/1.1" : "1.1") : string.Empty,
                            host, port);
                    }
                    result.StartTlsAdvertised = true;
                    // Grade and legacy detection
                    ComputeGrade(result);
                    if (result.LegacyEnabled) {
                        logger.WriteWarningCode(TlsCodes.LegacyEnabled, "Legacy TLS protocol negotiated on {0}:{1} - {2}", host, port, result.Protocol);
                    }
                    await ProbeOcspStaplingWithOpenSsl(host, port, result, logger, cancellationToken);
                }
                return result;
            }

            using var reader = new StreamReader(network);
            using var writer = new StreamWriter(network) { AutoFlush = true, NewLine = "\r\n" };
            await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
            timeoutCts.Token.ThrowIfCancellationRequested();
            var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            switch (protocol) {
                case MailProtocol.Smtp:
                    await writer.WriteLineAsync("EHLO example.com");
                    string? line;
                    while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger.WriteVerbose($"EHLO response: {line}");
                        if (line.StartsWith("250")) {
                            string capLine = line.Substring(4).Trim();
                            foreach (var part in capLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries)) {
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
                    break;
                case MailProtocol.Imap:
                    await writer.WriteLineAsync("A1 CAPABILITY");
                    while (true) {
                        var resp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                        timeoutCts.Token.ThrowIfCancellationRequested();
                    if (resp == null) {
                        break;
                    }
                    logger.WriteVerbose($"CAPABILITY response: {resp}");
                    if (resp.StartsWith("*")) {
                        var capLine = resp.Substring(1).Trim();
                        if (capLine.StartsWith("CAPABILITY", StringComparison.OrdinalIgnoreCase)) {
                            var caps = capLine.Substring(10).Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                            foreach (var cap in caps) {
                                    capabilities.Add(cap);
                                }
                            }
                        } else if (resp.StartsWith("A1", StringComparison.OrdinalIgnoreCase)) {
                            break;
                        }
                    }
                    result.StartTlsAdvertised = capabilities.Contains("STARTTLS");
                    break;
                case MailProtocol.Pop3:
                    await writer.WriteLineAsync("CAPA");
                    string? popLine;
                    while ((popLine = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger.WriteVerbose($"CAPA response: {popLine}");
                        if (popLine == ".") {
                            break;
                        }
                        capabilities.Add(popLine.Trim());
                    }
                    result.StartTlsAdvertised = capabilities.Contains("STLS");
                    if (!result.StartTlsAdvertised) {
                        await writer.WriteLineAsync("QUIT").WaitWithCancellation(timeoutCts.Token);
                        await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                        await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                        return result;
                    }
                    break;
            }

            if (!result.StartTlsAdvertised) {
                await writer.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                await writer.FlushAsync().WaitWithCancellation(timeoutCts.Token);
                await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
                return result;
            }

            var startTlsCommand = protocol switch {
                MailProtocol.Smtp => "STARTTLS",
                MailProtocol.Imap => "A2 STARTTLS",
                MailProtocol.Pop3 => "STLS",
                _ => "STARTTLS"
            };
            await writer.WriteLineAsync(startTlsCommand).WaitWithCancellation(timeoutCts.Token);
            var startTlsResp = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token);
            bool proceed = protocol switch {
                MailProtocol.Smtp => startTlsResp != null && startTlsResp.StartsWith("220"),
                MailProtocol.Imap => startTlsResp != null &&
                    startTlsResp.StartsWith("A2", StringComparison.OrdinalIgnoreCase) &&
                    startTlsResp.IndexOf("OK", StringComparison.OrdinalIgnoreCase) >= 0,
                MailProtocol.Pop3 => startTlsResp != null && startTlsResp.StartsWith("+OK"),
                _ => false
            };
            if (!proceed) {
                logger?.WriteVerbose($"{host}:{port} STARTTLS rejected: {startTlsResp}");
                return result;
            }

            using var sslStream = new SslStream(network, false, (sender, certificate, chain, errors) => {
                result.CertificateValid = errors == SslPolicyErrors.None;
                result.HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                result.Chain.Clear();
                result.ChainErrors.Clear();
                if (certificate is X509Certificate2 cert) {
                    result.Certificate = CertificateLoaderCompat.Clone(cert);
                    result.DaysToExpire = (int)(cert.NotAfter - DateTime.Now).TotalDays;
                    result.DaysValid = (int)(cert.NotAfter - cert.NotBefore).TotalDays;
                    result.IsExpired = cert.NotAfter < DateTime.Now;
                    result.CertificateSubject = cert.Subject;
                    result.CertificateIssuer = cert.Issuer;
                    result.CertificateNotBefore = cert.NotBefore;
                    result.CertificateNotAfter = cert.NotAfter;
                    result.CertificateThumbprint = cert.Thumbprint;
                    result.CertificateSerialNumber = cert.SerialNumber;
                    result.CertificateSignatureAlgorithm = cert.SignatureAlgorithm?.FriendlyName;
                    try {
                        result.PublicKeyAlgorithm = cert.PublicKey?.Oid?.FriendlyName;
                        // Prefer modern APIs over obsolete PublicKey.Key
                        int? size2 = null;
                        try { using var rsa2 = cert.GetRSAPublicKey(); if (rsa2 != null) size2 = rsa2.KeySize; } catch { }
                        if (!size2.HasValue) { try { using var ecdsa2 = cert.GetECDsaPublicKey(); if (ecdsa2 != null) size2 = ecdsa2.KeySize; } catch { } }
                        if (!size2.HasValue) { try { using var dsa2 = cert.GetDSAPublicKey(); if (dsa2 != null) size2 = dsa2.KeySize; } catch { } }
                        result.PublicKeySize = size2;
                    } catch { }
                    try {
                        foreach (var ext in cert.Extensions) {
                            if (ext.Oid?.Value == "2.5.29.17") {
                                var asn = new System.Security.Cryptography.AsnEncodedData(ext.Oid, ext.RawData);
                                var text = asn.Format(true);
                                foreach (var line in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)) {
                                    var idx = line.IndexOf("DNS Name=", StringComparison.OrdinalIgnoreCase);
                                    if (idx >= 0) {
                                        var name = line.Substring(idx + 9).Trim();
                                        if (!string.IsNullOrWhiteSpace(name)) result.CertificateDnsNames.Add(name);
                                    }
                                }
                            }
                        }
                    } catch { }
                    if (chain != null) {
                        foreach (var element in chain.ChainElements) {
                            result.Chain.Add(CertificateLoaderCompat.Clone(element.Certificate));
                        }
                        foreach (var status in chain.ChainStatus) {
                            result.ChainErrors.Add(status.Status);
                        }
                    }
                }
                return true;
            });

            try {
                await sslStream.AuthenticateAsClientAsync(host).WaitWithCancellation(timeoutCts.Token);
                PopulateNegotiatedTlsDetails(result, sslStream);
                try {
                    var suite = result.CipherSuite ?? string.Empty;
                    if (!string.IsNullOrEmpty(suite)) {
                        var s = suite.ToUpperInvariant();
                        bool weak = s.Contains("3DES") || s.Contains("RC4") || s.Contains("_CBC_");
                        if (s.Contains("_SHA") && !s.Contains("SHA256") && !s.Contains("SHA384") && !s.Contains("SHA512")) weak = true;
                        if (weak) {
                            logger?.WriteWarningCode(TlsCodes.WeakCipherNegotiated, "Weak cipher negotiated on {0}:{1}: {2}", host, port, suite);
                        } else {
                            logger?.WriteInformationCode(MailTlsCodes.StrongCipherSuite, "Strong cipher negotiated on {0}:{1}: {2}", host, port, suite);
                        }
                    }
                    if (result.DhKeyBits > 0 && result.DhKeyBits < 2048) {
                        logger?.WriteWarningCode(TlsCodes.WeakKeyExchange, "Weak DH key size {0} bits negotiated on {1}:{2}", result.DhKeyBits, host, port);
                    }
                } catch { }
                try {
                    using var secureWriter = new StreamWriter(sslStream) { AutoFlush = true, NewLine = "\r\n" };
                    await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                } catch (ObjectDisposedException) {
                    logger?.WriteVerbose($"TLS session closed before QUIT on {host}:{port} (STARTTLS)");
                } catch (IOException ioex) {
                    logger?.WriteVerbose($"TLS write failed (QUIT) on {host}:{port} - {ioex.Message}");
                }
                if (result.CertificateValid && result.ChainValid && result.HostnameMatch && !result.IsExpired) {
                    logger?.WriteInformationCode(MailTlsCodes.CertificateValid, "Valid certificate on {0}:{1}", host, port);
                }
            } catch (AuthenticationException ex) {
                SetFailure(result, ex);
                logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
            } catch (ObjectDisposedException odex) {
                SetFailure(result, odex);
                logger?.WriteVerbose($"TLS stream disposed during operation on {host}:{port} - {odex.Message}");
            } catch (IOException ioex) {
                SetFailure(result, ioex);
                logger?.WriteVerbose($"TLS I/O error on {host}:{port} - {ioex.Message}");
            } finally {
                try { result.Protocol = sslStream.SslProtocol; } catch (ObjectDisposedException) { result.Protocol = SslProtocols.None; }
                result.SupportsTls13 = (int)result.Protocol == 12288;
                result.Tls13Used = result.SupportsTls13;
                // Probe protocol support (best-effort)
                await ProbeProtocolSupport(host, port, result, cancellationToken);
                if (result.SupportsTls10 || result.SupportsTls11) {       
                    logger?.WriteWarningCode(TlsCodes.LegacyOffered, "Server offers legacy TLS ({0}{1}) on {2}:{3}",
                        result.SupportsTls10 ? "1.0" : string.Empty,
                        result.SupportsTls11 ? (result.SupportsTls10 ? "/1.1" : "1.1") : string.Empty,
                        host, port);
                }
                ComputeGrade(result);
                if (result.LegacyEnabled) {
                    logger?.WriteWarningCode(TlsCodes.LegacyEnabled, "Legacy TLS protocol negotiated on {0}:{1} - {2}", host, port, result.Protocol);
                }
                await ProbeOcspStaplingWithOpenSsl(host, port, result, logger, cancellationToken);
            }
        } catch (Exception ex) {
            SetFailure(result, ex);
            logger?.WriteErrorCode(MailTlsCodes.TlsCheckFailed, "TLS check failed for {0}:{1} - {2}", host, port, ex.Message);
        }

        return result;
    }

    private static void SetFailure(TlsResult result, Exception exception) {
        if (result == null || exception == null) {
            return;
        }

        result.FailureReason = CertificateAnalysis.BuildFailureReason(exception);
        result.FailureKind = CertificateFailureClassifier.Classify(exception);
    }

    private static async Task ProbeProtocolSupport(string host, int port, TlsResult result, CancellationToken token) {
        async Task<bool> TryHandshake(SslProtocols proto) {
            try {
                using var client = new TcpClient();
                await client.ConnectAsync(host, port).WaitWithCancellation(token);
                using var ssl = new SslStream(client.GetStream(), false, static (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(host, null, proto, false).WaitWithCancellation(token);
                return ssl.SslProtocol == proto;
            } catch { return false; }
        }
        result.SupportsTls13 = result.SupportsTls13 || await TryHandshake((SslProtocols)12288);
        result.SupportsTls12 = await TryHandshake(SslProtocols.Tls12);
        // We intentionally probe legacy protocols to report legacy support. Suppress deprecation warnings locally.
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 obsolete warnings
        result.SupportsTls11 = await TryHandshake(SslProtocols.Tls11);
        result.SupportsTls10 = await TryHandshake(SslProtocols.Tls);
#pragma warning restore SYSLIB0039
    }

    private static async Task ProbeOcspStaplingWithOpenSsl(string host, int port, TlsResult result, InternalLogger? logger, CancellationToken token) {
        try {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
            var psi = new System.Diagnostics.ProcessStartInfo {
                FileName = "openssl",
                Arguments = $"s_client -connect {host}:{port} -servername {host} -starttls {(port == 25 ? "smtp" : port == 110 ? "pop3" : port == 143 ? "imap" : "smtp")} -status -brief",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            var readOut = proc.StandardOutput.ReadToEndAsync();
            var readErr = proc.StandardError.ReadToEndAsync();
            var delayTask = Task.Delay(TimeSpan.FromSeconds(5), cts.Token);
#if NET8_0_OR_GREATER
            var waitTask = proc.WaitForExitAsync(cts.Token);
#else
            var waitTask = Task.Run(() => { while (!proc.HasExited) { if (cts.Token.IsCancellationRequested) break; Thread.Sleep(25); } }, cts.Token);
#endif
            await Task.WhenAny(delayTask, waitTask);
            string output = string.Empty;
            try { output = await readOut; } catch { }
            string error = string.Empty;
            try { error = await readErr; } catch { }
            var text = (output ?? string.Empty) + "\n" + (error ?? string.Empty);
            if (string.IsNullOrWhiteSpace(text)) return;
            bool present = text.IndexOf("OCSP Response Status:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           text.IndexOf("OCSP Response Data:", StringComparison.OrdinalIgnoreCase) >= 0;
            bool explicitlyMissing = text.IndexOf("OCSP response: no response sent", StringComparison.OrdinalIgnoreCase) >= 0;
            result.OcspStaplingPresent = present && !explicitlyMissing;
            if (result.OcspStaplingPresent == true) {
                logger?.WriteInformationCode(TlsCodes.OcspStaplingPresent, "Server stapled an OCSP response on {0}:{1}", host, port);
            } else {
                logger?.WriteWarningCode(TlsCodes.OcspStaplingMissing, "OCSP stapling not detected on {0}:{1}", host, port);
            }
        } catch { }
    }

    private static void ComputeGrade(TlsResult r) {
        // Legacy detection
        // Legacy protocols are checked to assess security posture; suppress deprecation warnings in this check only.
#pragma warning disable SYSLIB0039, CS0618
        r.LegacyEnabled = r.Protocol == SslProtocols.Tls || r.Protocol == SslProtocols.Ssl3 || r.Protocol == SslProtocols.Tls11;
#pragma warning restore SYSLIB0039, CS0618
        // Coarse grading
        if (r.IsExpired || !r.CertificateValid || !r.ChainValid || !r.HostnameMatch) {
            r.GradeLevel = GradeLevel.F;
            return;
        }
        if (r.Tls13Used) { r.GradeLevel = GradeLevel.A; return; }
        if (r.Protocol == SslProtocols.Tls12) {
            r.GradeLevel = GradeLevel.B;
            return;
        }
        // Suppress deprecation warnings for legacy protocol grading branch
#pragma warning disable SYSLIB0039
        if (r.Protocol == SslProtocols.Tls11 || r.Protocol == SslProtocols.Tls) {
            r.GradeLevel = GradeLevel.D;
            return;
        }
#pragma warning restore SYSLIB0039
        r.GradeLevel = GradeLevel.C;
    }
}
