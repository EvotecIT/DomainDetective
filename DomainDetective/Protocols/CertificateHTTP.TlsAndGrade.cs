using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using DomainDetective.Helpers;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using DnsClientX;

namespace DomainDetective {
    public partial class CertificateAnalysis : IHasAssessments {
        private static bool IsSelfSignedCertificate(X509Certificate2? certificate) {
            if (certificate == null) {
                return false;
            }

            var subject = certificate.Subject;
            var issuer = certificate.Issuer;
            if (string.IsNullOrWhiteSpace(subject) || string.IsNullOrWhiteSpace(issuer)) {
                return false;
            }

            return string.Equals(subject, issuer, StringComparison.OrdinalIgnoreCase);
        }

        private void PopulateKeyInfo() {
            var certificate = Certificate;
            if (certificate == null) {
                KeyAlgorithm = string.Empty;
                KeySize = 0;
                WeakKey = false;
                Sha1Signature = false;
                RsaPssSignature = false;
                PopulateExtendedKeyUsageInfo(null);
                return;
            }
            KeyAlgorithm = certificate.PublicKey?.Oid?.FriendlyName ?? certificate.PublicKey?.Oid?.Value ?? string.Empty;
            try {
                // PublicKey.Key is obsolete in modern runtimes; prefer algorithm-specific helpers.
#if NET8_0_OR_GREATER
                var keySize = 0;
                using (var rsa = certificate.GetRSAPublicKey()) {
                    if (rsa != null) {
                        keySize = rsa.KeySize;
                    }
                }
                if (keySize == 0) {
                    using (var ecdsa = certificate.GetECDsaPublicKey()) {
                        if (ecdsa != null) {
                            keySize = ecdsa.KeySize;
                        }
                    }
                }
                if (keySize == 0) {
                    using (var dsa = certificate.GetDSAPublicKey()) {
                        keySize = dsa?.KeySize ?? 0;
                    }
                }
                KeySize = keySize;
#else
                KeySize = certificate.PublicKey?.Key?.KeySize ?? 0;
#endif
            } catch {
                KeySize = 0;
            }
            WeakKey = IsWeakPublicKey(KeyAlgorithm, KeySize);
            var oid = certificate.SignatureAlgorithm?.Value ?? string.Empty;
            Sha1Signature = oid == "1.2.840.113549.1.1.5" ||
                            oid == "1.2.840.10040.4.3" ||
                            oid == "1.3.14.3.2.29";
            RsaPssSignature = oid == "1.2.840.113549.1.1.10";
            PopulateExtendedKeyUsageInfo(certificate);
        }

        private static bool IsWeakPublicKey(string? keyAlgorithm, int keySize) {
            if (keySize <= 0) {
                return false;
            }

            var algorithm = keyAlgorithm ?? string.Empty;
            if (algorithm.IndexOf("EC", StringComparison.OrdinalIgnoreCase) >= 0 ||
                algorithm.IndexOf("ECC", StringComparison.OrdinalIgnoreCase) >= 0 ||
                algorithm.IndexOf("ECDSA", StringComparison.OrdinalIgnoreCase) >= 0) {
                return keySize < 256;
            }

            if (algorithm.IndexOf("RSA", StringComparison.OrdinalIgnoreCase) >= 0 ||
                algorithm.IndexOf("DSA", StringComparison.OrdinalIgnoreCase) >= 0 ||
                algorithm.IndexOf("DH", StringComparison.OrdinalIgnoreCase) >= 0 ||
                algorithm.IndexOf("Diffie", StringComparison.OrdinalIgnoreCase) >= 0) {
                return keySize < 2048;
            }

            return keySize < 2048;
        }

        private void PopulateExtendedKeyUsageInfo(X509Certificate2? certificate) {
            HasEnhancedKeyUsageExtension = false;
            HasAnyExtendedKeyUsageOid = false;
            AllowsServerAuthentication = false;
            AllowsClientAuthentication = false;
            AllowsSecureEmail = false;
            AuthenticationProfile = CertificateAuthenticationProfileClassifier.NoEkuExtension;
            ExtendedKeyUsageOids.Clear();
            ExtendedKeyUsageFriendlyNames.Clear();

            var parsed = CertificateExtendedKeyUsageAnalyzer.Analyze(certificate);
            HasEnhancedKeyUsageExtension = parsed.HasEnhancedKeyUsageExtension;
            HasAnyExtendedKeyUsageOid = parsed.HasAnyExtendedKeyUsageOid;
            AllowsServerAuthentication = parsed.AllowsServerAuthentication;
            AllowsClientAuthentication = parsed.AllowsClientAuthentication;
            AllowsSecureEmail = parsed.AllowsSecureEmail;
            AuthenticationProfile = string.IsNullOrWhiteSpace(parsed.AuthenticationProfile)
                ? CertificateAuthenticationProfileClassifier.Classify(parsed)
                : parsed.AuthenticationProfile;
            ExtendedKeyUsageOids.AddRange(parsed.Oids);
            ExtendedKeyUsageFriendlyNames.AddRange(parsed.FriendlyNames);
        }

#pragma warning disable CA2000 // Dispose objects before losing scope - returned TcpClient is disposed by caller
        private async Task<TcpClient> ConnectWithProxy(string host, int port, CancellationToken token) {
            var proxy = Environment.GetEnvironmentVariable("HTTPS_PROXY") ??
                        Environment.GetEnvironmentVariable("https_proxy") ??
                        Environment.GetEnvironmentVariable("HTTP_PROXY") ??
                        Environment.GetEnvironmentVariable("http_proxy");
            if (!string.IsNullOrEmpty(proxy)) {
                var p = new Uri(proxy);
                token.ThrowIfCancellationRequested();
                TcpClient tcp = new();
                try {
                    // Closing the owned socket interrupts Framework's non-cancelable
                    // connect/read overloads. Await them through completion before returning.
                    using var registration = token.Register(() => tcp.Dispose());
                    await tcp.ConnectAsync(p.Host, p.Port).ConfigureAwait(false);
                    var stream = tcp.GetStream();
                    var connectCmd = $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n";
                    var buffer = System.Text.Encoding.ASCII.GetBytes(connectCmd);
                    await stream.WriteAsync(buffer, 0, buffer.Length, token).ConfigureAwait(false);
                    await stream.FlushAsync(token).ConfigureAwait(false);
                    using var reader = new StreamReader(stream, System.Text.Encoding.ASCII, false, 1024, true);
                    string? line = await reader.ReadLineAsync().ConfigureAwait(false);
                    if (line == null || (!line.StartsWith("HTTP/1.1 200") && !line.StartsWith("HTTP/1.0 200"))) {
                        throw new IOException($"Proxy CONNECT failed: {line}");
                    }
                    while (!string.IsNullOrEmpty(await reader.ReadLineAsync().ConfigureAwait(false))) { }
                    token.ThrowIfCancellationRequested();
                    return tcp;
                } catch {
                    tcp.Dispose();
                    token.ThrowIfCancellationRequested();
                    throw;
                }
            }
            return await ConnectDirectAsync(
                    host,
                    port,
                    token,
                    captureRemoteAddress: false)
                .ConfigureAwait(false);
        }
#pragma warning restore CA2000

        private async Task PopulateTlsInfo(Uri uri, int port, CancellationToken token) {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(Timeout);
            using var tcp = await ConnectWithProxy(uri.Host, port, timeoutCts.Token);
            using var ssl = new SslStream(tcp.GetStream(), false, static (_, _, _, _) => true);
            try
            {
                await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.None, !SkipRevocation).WaitWithCancellation(timeoutCts.Token);
            }
            catch (Exception ex)
            {
                throw NormalizeProbeException(ex, token, timeoutCts);
            }
            TlsProtocol = ssl.SslProtocol;
            Tls13Used = (int)ssl.SslProtocol == 12288;
            var tlsInfo = TlsNegotiationInfoFactory.Create(ssl);
            CipherAlgorithm = tlsInfo.CipherAlgorithm;
            CipherStrength = tlsInfo.CipherStrength;
            CipherSuite = tlsInfo.CipherSuite;
            DhKeyBits = tlsInfo.DhKeyBits;
        }

        private void PopulateSctAndTlsFeature(InternalLogger logger)
        {
            SctCount = 0;
            OcspMustStaple = false;
            try {
                if (Certificate == null) return;
                var parser = new Org.BouncyCastle.X509.X509CertificateParser();
                var bcCert = parser.ReadCertificate(Certificate.RawData);
                // SCT list extension: 1.3.6.1.4.1.11129.2.4.2
                var sctExt = bcCert.GetExtensionValue(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.4.1.11129.2.4.2"));
                if (sctExt != null)
                {
                    try
                    {
                        // Very coarse approximation: count plausible SCT markers
                        var bytes = sctExt.GetOctets();
                        int count = 0;
                        for (int i = 0; i < bytes.Length - 33; i++)
                        {
                            if (bytes[i] == 0x00) count++;
                        }
                        SctCount = System.Math.Max(0, count / 32);
                    }
                    catch { SctCount = 1; }
                }
                if (SctCount == 0)
                {
                    logger?.WriteInformationCode(TlsCodes.SctMissing, "No embedded SCTs found in certificate");
                }

                // TLS Feature extension (OCSP Must-Staple): 1.3.6.1.5.5.7.1.24 with status_request (5)
                var tlsFeat = bcCert.GetExtensionValue(new Org.BouncyCastle.Asn1.DerObjectIdentifier("1.3.6.1.5.5.7.1.24"));
                if (tlsFeat != null)
                {
                    try
                    {
                        var seq = (Org.BouncyCastle.Asn1.Asn1Sequence)Org.BouncyCastle.Asn1.Asn1Object.FromByteArray(tlsFeat.GetOctets());
                        foreach (var o in seq)
                        {
                            if (o is Org.BouncyCastle.Asn1.DerInteger di && di.IntValueExact == 5) { OcspMustStaple = true; break; }
                        }
                    }
                    catch { }
                }
                if (!OcspMustStaple)
                {
                    logger?.WriteInformationCode(TlsCodes.OcspMustStapleMissing, "Certificate does not include OCSP Must-Staple (TLS Feature)");
                }
            } catch { }
        }

        private async Task ProbeOcspStaplingWithOpenSsl(Uri uri, int port, InternalLogger logger, CancellationToken token)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(Timeout);
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = $"s_client -connect {uri.Host}:{port} -servername {uri.Host} -status -brief",
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return;
                var captured = await ProcessOutputCapture.ReadUntilExitAsync(proc, cts.Token, token).ConfigureAwait(false);
                OcspStaplingPresent = OcspStaplingEvidence.Parse(captured.Output, captured.Error);
                if (OcspStaplingPresent == null) return;
                if (OcspStaplingPresent == true)
                {
                    logger?.WriteInformationCode(TlsCodes.OcspStaplingPresent, "Server stapled an OCSP response on {0}:{1}", uri.Host, port);
                }
                else
                {
                    logger?.WriteWarningCode(TlsCodes.OcspStaplingMissing, "OCSP stapling not detected on {0}:{1}", uri.Host, port);
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch { }
        }

        private async Task ProbeProtocolSupport(Uri uri, int port, InternalLogger logger, CancellationToken token)
        {
            SupportsTls10 = false; SupportsTls11 = false; SupportsTls12 = false; SupportsTls13 = false;
            ProtocolSupportComplete = LegacyProtocolSupportComplete = false;
            async Task<(SslProtocols Protocol, bool Supported, bool Complete)> TryHandshake(SslProtocols proto)
            {
                token.ThrowIfCancellationRequested();
                if (TlsProtocol == proto) { return (proto, true, true); }
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(Timeout == System.Threading.Timeout.InfiniteTimeSpan || ProtocolProbeTimeout < Timeout
                    ? ProtocolProbeTimeout : Timeout);
                Helpers.TlsAlertEvidenceStream? evidence = null;
                try {
                    using var tcp = await ConnectWithProxy(uri.Host, port, timeoutCts.Token);
                    using var observed = new Helpers.TlsAlertEvidenceStream(tcp.GetStream(), leaveOpen: true);
                    evidence = observed;
                    using var ssl = new System.Net.Security.SslStream(observed, false, static (_, _, _, _) => true);
#if NET8_0_OR_GREATER
                    var options = new System.Net.Security.SslClientAuthenticationOptions { TargetHost = uri.Host, EnabledSslProtocols = proto, CertificateRevocationCheckMode = SkipRevocation ? System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck : System.Security.Cryptography.X509Certificates.X509RevocationMode.Online };
                    await ssl.AuthenticateAsClientAsync(options, timeoutCts.Token);
#else
                    using var registration = timeoutCts.Token.Register(() => ssl.Dispose());
                    await ssl.AuthenticateAsClientAsync(uri.Host, null, proto, !SkipRevocation);
#endif
                    timeoutCts.Token.ThrowIfCancellationRequested();
                    return (proto, ssl.SslProtocol == proto, ssl.SslProtocol == proto);
                } catch (Exception) when (token.IsCancellationRequested) {
                    token.ThrowIfCancellationRequested();
                    throw;
                } catch (Exception ex) when (ex is not OutOfMemoryException) {
                    return (proto, false, evidence?.SawProtocolVersionRejection == true);
                }
            }
            // The numeric TLS 1.3 value also permits Framework hosts to report supported
            // runtime capability; a local policy failure remains inconclusive.
            var protocols = new[] { (SslProtocols)12288, SslProtocols.Tls12, (SslProtocols)768, (SslProtocols)192 };
            var results = await Task.WhenAll(protocols.Select(TryHandshake)).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            SupportsTls13 = results.Any(result => (int)result.Protocol == 12288 && result.Supported);
            SupportsTls12 = results.Any(result => result.Protocol == SslProtocols.Tls12 && result.Supported);
            SupportsTls11 = results.Any(result => (int)result.Protocol == 768 && result.Supported);
            SupportsTls10 = results.Any(result => (int)result.Protocol == 192 && result.Supported);
            ProtocolSupportComplete = results.All(result => result.Complete);
            LegacyProtocolSupportComplete = results.Where(result => (int)result.Protocol is 768 or 192).All(result => result.Complete);
            if (!ProtocolSupportComplete) {
                logger?.WriteInformationCode("TLS.ProtocolSupport.Incomplete", "TLS version coverage is incomplete; a failed local or network probe does not establish absent protocol support.");
            }
            if (SupportsTls10 || SupportsTls11)
            {
                logger?.WriteWarningCode(TlsCodes.LegacyOffered, "Server offers legacy TLS ({0}{1}) on {2}:{3}",
                    SupportsTls10 ? "1.0" : string.Empty,
                    SupportsTls11 ? (SupportsTls10 ? "/1.1" : "1.1") : string.Empty,
                    uri.Host, port);
            }
        }

        private void ComputeGrade(InternalLogger logger) {
            // Legacy detection when TLS details are known (suppress deprecation warnings in this check only)
#pragma warning disable SYSLIB0039, CS0618
            LegacyEnabled = TlsProtocol == SslProtocols.Tls || TlsProtocol == SslProtocols.Ssl3 || TlsProtocol == SslProtocols.Tls11;
#pragma warning restore SYSLIB0039, CS0618
            if (LegacyEnabled) {
                logger?.WriteWarningCode(TlsCodes.LegacyEnabled, "Legacy TLS protocol negotiated on {0} - {1}", Url ?? Subject, TlsProtocol);
            }
            // Weak cipher negotiated advisory
            try {
                var suite = CipherSuite ?? string.Empty;
                if (!string.IsNullOrEmpty(suite) && (suite.IndexOf("3DES", StringComparison.OrdinalIgnoreCase) >= 0 || suite.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    logger?.WriteWarningCode(TlsCodes.WeakCipherNegotiated, "Weak cipher negotiated on {0}: {1}", Url ?? Subject, suite);
                }
            } catch { }

            // Coarse grading aligned to MailTlsAnalysis
            if (IsExpired || !IsValid || !HostnameMatch) { GradeLevel = GradeLevel.F; return; }
            if (Tls13Used) { GradeLevel = GradeLevel.A; return; }
            if (TlsProtocol == SslProtocols.Tls12 && !LegacyEnabled) { GradeLevel = GradeLevel.B; return; }
            // Suppress deprecation warnings for legacy grading branch
#pragma warning disable SYSLIB0039
            if (TlsProtocol == SslProtocols.Tls11 || TlsProtocol == SslProtocols.Tls) { GradeLevel = GradeLevel.D; return; }
#pragma warning restore SYSLIB0039
            // When TLS details are unknown, fall back to pass (valid cert) grade
            GradeLevel = !string.IsNullOrEmpty(Certificate?.Subject) ? GradeLevel.C : GradeLevel.F;
        }
    }

}
