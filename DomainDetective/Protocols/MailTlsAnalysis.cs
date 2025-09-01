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
public class MailTlsAnalysis : IHasAssessments {
    public string? Subject { get; set; }
    /// <summary>Supported mail protocols.</summary>
    public enum MailProtocol {
        Smtp,
        Imap,
        Pop3
    }

    /// <summary>Result of a TLS check.</summary>
    public class TlsResult {
        public bool StartTlsAdvertised { get; set; }
        public bool CertificateValid { get; set; }
        public int DaysToExpire { get; set; }
        public int DaysValid { get; set; }
        public bool IsExpired { get; set; }
        public SslProtocols Protocol { get; set; }
        public bool SupportsTls13 { get; set; }
        public bool SupportsTls12 { get; set; }
        public bool SupportsTls11 { get; set; }
        public bool SupportsTls10 { get; set; }
        public bool Tls13Used { get; set; }
        public bool HostnameMatch { get; set; }
        public CipherAlgorithmType CipherAlgorithm { get; set; }
        public int CipherStrength { get; set; }
        public string CipherSuite { get; set; } = string.Empty;
        public int DhKeyBits { get; set; }
        public X509Certificate2? Certificate { get; set; }
        public List<X509Certificate2> Chain { get; } = new();
        public List<X509ChainStatusFlags> ChainErrors { get; } = new();
        public bool ChainValid => ChainErrors.Count == 0;

        // Flattened certificate fields for easier consumption
        public string? CertificateSubject { get; set; }
        public string? CertificateIssuer { get; set; }
        public DateTime? CertificateNotBefore { get; set; }
        public DateTime? CertificateNotAfter { get; set; }
        public string? CertificateThumbprint { get; set; }
        public string? CertificateSerialNumber { get; set; }
        public string? CertificateSignatureAlgorithm { get; set; }
        public string? PublicKeyAlgorithm { get; set; }
        public int? PublicKeySize { get; set; }
        public List<string> CertificateDnsNames { get; } = new();
        public GradeLevel GradeLevel { get; set; } = GradeLevel.Unknown;
        public bool LegacyEnabled { get; set; }
        public bool? OcspStaplingPresent { get; set; }
    }

    /// <summary>Stores results for each server.</summary>
    public Dictionary<string, TlsResult> ServerResults { get; } = new();
    /// <summary>Timeout for connections.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Structured assessments captured during mail TLS checks.</summary>
    public List<Assessment> Assessments { get; } = new();
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

    private async Task<TlsResult> CheckTls(MailProtocol protocol, string host, int port, InternalLogger logger, CancellationToken cancellationToken) {
        string category = protocol switch { MailProtocol.Smtp => "SMTPTLS", MailProtocol.Imap => "IMAPTLS", MailProtocol.Pop3 => "POP3TLS", _ => "MAILTLS" };
        using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: category, target: $"{host}:{port}");
        var result = new TlsResult();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(Timeout);
        try {
            using var client = new TcpClient();
#if NET6_0_OR_GREATER
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
                        result.Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
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
                            result.PublicKeySize = cert.PublicKey?.Key?.KeySize;
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
                    try {
                        var suite = result.CipherSuite ?? string.Empty;
                        if (!string.IsNullOrEmpty(suite) && (suite.IndexOf("3DES", System.StringComparison.OrdinalIgnoreCase) >= 0 || suite.IndexOf("RC4", System.StringComparison.OrdinalIgnoreCase) >= 0)) {
                            logger?.WriteWarningCode(TlsCodes.WeakCipherNegotiated, "Weak cipher negotiated on {0}:{1}: {2}", host, port, suite);
                        }
                    } catch { }
                    using var secureWriter = new StreamWriter(ssl) { AutoFlush = true, NewLine = "\r\n" };
                    await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
                } catch (AuthenticationException ex) {
                    logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
                } finally {
                    result.Protocol = ssl.SslProtocol;
#if NET8_0_OR_GREATER
                    result.SupportsTls13 = result.Protocol == SslProtocols.Tls13;
                    result.Tls13Used = result.SupportsTls13;
#else
                    result.SupportsTls13 = (int)result.Protocol == 12288;
                    result.Tls13Used = result.SupportsTls13;
#endif
                    // Probe protocol support (best-effort)
                    await ProbeProtocolSupport(host, port, result, cancellationToken);
                    if (result.SupportsTls10 || result.SupportsTls11) {
                        logger?.WriteWarningCode(TlsCodes.LegacyOffered, "Server offers legacy TLS ({0}{1}) on {2}:{3}",
                            result.SupportsTls10 ? "1.0" : string.Empty,
                            result.SupportsTls11 ? (result.SupportsTls10 ? "/1.1" : "1.1") : string.Empty,
                            host, port);
                    }
                    result.StartTlsAdvertised = true;
                    // Grade and legacy detection
                    ComputeGrade(result);
                    if (result.LegacyEnabled) {
                        logger?.WriteWarningCode(TlsCodes.LegacyEnabled, "Legacy TLS protocol negotiated on {0}:{1} - {2}", host, port, result.Protocol);
                    }
                    await ProbeOcspStaplingWithOpenSsl(host, port, result, logger, cancellationToken);
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
            switch (protocol) {
                case MailProtocol.Smtp:
                    await writer.WriteLineAsync("EHLO example.com");
                    string line;
                    while ((line = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger?.WriteVerbose($"EHLO response: {line}");
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
                        logger?.WriteVerbose($"CAPABILITY response: {resp}");
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
                    string popLine;
                    while ((popLine = await reader.ReadLineAsync().WaitWithCancellation(timeoutCts.Token)) != null) {
                        timeoutCts.Token.ThrowIfCancellationRequested();
                        logger?.WriteVerbose($"CAPA response: {popLine}");
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
                    result.Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
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
                        result.PublicKeySize = cert.PublicKey?.Key?.KeySize;
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
                if (sslStream.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman) {
                    result.DhKeyBits = sslStream.KeyExchangeStrength;
                }
                try {
                    var suite = result.CipherSuite ?? string.Empty;
                    if (!string.IsNullOrEmpty(suite) && (suite.IndexOf("3DES", System.StringComparison.OrdinalIgnoreCase) >= 0 || suite.IndexOf("RC4", System.StringComparison.OrdinalIgnoreCase) >= 0)) {
                        logger?.WriteWarningCode(TlsCodes.WeakCipherNegotiated, "Weak cipher negotiated on {0}:{1}: {2}", host, port, suite);
                    }
                } catch { }
                using var secureWriter = new StreamWriter(sslStream) { AutoFlush = true, NewLine = "\r\n" };
                await secureWriter.WriteLineAsync(GetQuitCommand(protocol)).WaitWithCancellation(timeoutCts.Token);
            } catch (AuthenticationException ex) {
                logger?.WriteVerbose($"TLS authentication failed for {host}:{port} - {ex.Message}");
            } finally {
                result.Protocol = sslStream.SslProtocol;
#if NET8_0_OR_GREATER
                result.SupportsTls13 = result.Protocol == SslProtocols.Tls13;
                result.Tls13Used = result.SupportsTls13;
#else
                result.SupportsTls13 = (int)result.Protocol == 12288;
                result.Tls13Used = result.SupportsTls13;
#endif
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
            logger?.WriteErrorCode(MailTlsCodes.TlsCheckFailed, "TLS check failed for {0}:{1} - {2}", host, port, ex.Message);
        }

        return result;
    }

    private static async Task ProbeProtocolSupport(string host, int port, TlsResult result, CancellationToken token) {
        async Task<bool> TryHandshake(SslProtocols proto) {
            try {
                using var client = new TcpClient();
#if NET6_0_OR_GREATER
                await client.ConnectAsync(host, port, token);
#else
                await client.ConnectAsync(host, port).WaitWithCancellation(token);
#endif
                using var ssl = new SslStream(client.GetStream(), false, static (_, _, _, _) => true);
#if NET5_0_OR_GREATER
                var options = new SslClientAuthenticationOptions { TargetHost = host, EnabledSslProtocols = proto, CertificateRevocationCheckMode = X509RevocationMode.NoCheck };
                await ssl.AuthenticateAsClientAsync(options, token);
#else
                await ssl.AuthenticateAsClientAsync(host, null, proto, false).WaitWithCancellation(token);
#endif
                return ssl.SslProtocol == proto;
            } catch { return false; }
        }
#if NET5_0_OR_GREATER
        result.SupportsTls13 = result.SupportsTls13 || await TryHandshake(SslProtocols.Tls13);
#endif
        result.SupportsTls12 = await TryHandshake(SslProtocols.Tls12);
        result.SupportsTls11 = await TryHandshake(SslProtocols.Tls11);
        result.SupportsTls10 = await TryHandshake(SslProtocols.Tls);
    }

    private static async Task ProbeOcspStaplingWithOpenSsl(string host, int port, TlsResult result, InternalLogger logger, CancellationToken token) {
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
#if NET5_0_OR_GREATER
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
        r.LegacyEnabled = r.Protocol == SslProtocols.Tls || r.Protocol == SslProtocols.Ssl3 || r.Protocol == SslProtocols.Tls11;
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
        if (r.Protocol == SslProtocols.Tls11 || r.Protocol == SslProtocols.Tls) {
            r.GradeLevel = GradeLevel.D;
            return;
        }
        r.GradeLevel = GradeLevel.C;
    }
}
