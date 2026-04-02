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
        private static async Task<TcpClient> ConnectWithProxy(string host, int port, CancellationToken token) {
            var proxy = Environment.GetEnvironmentVariable("HTTPS_PROXY") ??
                        Environment.GetEnvironmentVariable("https_proxy") ??
                        Environment.GetEnvironmentVariable("HTTP_PROXY") ??
                        Environment.GetEnvironmentVariable("http_proxy");
            TcpClient tcp = new();
            if (!string.IsNullOrEmpty(proxy)) {
                var p = new Uri(proxy);
                await tcp.ConnectAsync(p.Host, p.Port).WaitWithCancellation(token);
                var stream = tcp.GetStream();
                var connectCmd = $"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n";
                var buffer = System.Text.Encoding.ASCII.GetBytes(connectCmd);
                await stream.WriteAsync(buffer, 0, buffer.Length, token);
                await stream.FlushAsync(token);
                using var reader = new StreamReader(stream, System.Text.Encoding.ASCII, false, 1024, true);
                string? line = await reader.ReadLineAsync();
                if (line == null || (!line.StartsWith("HTTP/1.1 200") && !line.StartsWith("HTTP/1.0 200"))) {
                    throw new IOException($"Proxy CONNECT failed: {line}");
                }
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync())) { }
            } else {
                await tcp.ConnectAsync(host, port).WaitWithCancellation(token);
            }
            return tcp;
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
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                cts.CancelAfter(Timeout);
                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "openssl",
                    Arguments = $"s_client -connect {uri.Host}:{port} -servername {uri.Host} -status -brief",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc == null) return;
                var readOut = proc.StandardOutput.ReadToEndAsync();
                var readErr = proc.StandardError.ReadToEndAsync();
                var delayTask = Task.Delay(Timeout, cts.Token);
#if NET8_0_OR_GREATER
                var waitTask = proc.WaitForExitAsync(cts.Token);
#else
                var waitTask = Task.Run(() => { while (!proc.HasExited) { if (cts.Token.IsCancellationRequested) break; Thread.Sleep(25); } }, cts.Token);
#endif
                var completed = await Task.WhenAny(delayTask, waitTask);
                if (completed != waitTask) {
                    try { if (!proc.HasExited) { proc.Kill(); } } catch { }
                }
                string output = await ReadWithTimeout(readOut, TimeSpan.FromSeconds(1), cts.Token);
                string error = await ReadWithTimeout(readErr, TimeSpan.FromSeconds(1), cts.Token);
                var text = (output ?? string.Empty) + "\n" + (error ?? string.Empty);
                if (string.IsNullOrWhiteSpace(text)) return;
                bool present = text.IndexOf("OCSP Response Status:", StringComparison.OrdinalIgnoreCase) >= 0 ||
                               text.IndexOf("OCSP Response Data:", StringComparison.OrdinalIgnoreCase) >= 0;
                bool explicitlyMissing = text.IndexOf("OCSP response: no response sent", StringComparison.OrdinalIgnoreCase) >= 0;
                OcspStaplingPresent = present && !explicitlyMissing;
                if (OcspStaplingPresent == true)
                {
                    logger?.WriteInformationCode(TlsCodes.OcspStaplingPresent, "Server stapled an OCSP response on {0}:{1}", uri.Host, port);
                }
                else
                {
                    logger?.WriteWarningCode(TlsCodes.OcspStaplingMissing, "OCSP stapling not detected on {0}:{1}", uri.Host, port);
                }
            }
            catch { }
        }

        private static async Task<string> ReadWithTimeout(Task<string> readTask, TimeSpan timeout, CancellationToken token) {
            try {
                var completed = await Task.WhenAny(readTask, Task.Delay(timeout, token));
                if (completed == readTask) {
                    return await readTask;
                }
            } catch {
            }
            return string.Empty;
        }

        private async Task ProbeProtocolSupport(Uri uri, int port, InternalLogger logger, CancellationToken token)
        {
            SupportsTls10 = false; SupportsTls11 = false; SupportsTls12 = false; SupportsTls13 = false;
            async Task<bool> TryHandshake(System.Security.Authentication.SslProtocols proto)
            {
                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeoutCts.CancelAfter(Timeout);
                try {
                    using var tcp = await ConnectWithProxy(uri.Host, port, timeoutCts.Token);
                    using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, static (_, _, _, _) => true);
#if NET8_0_OR_GREATER
                    var options = new System.Net.Security.SslClientAuthenticationOptions { TargetHost = uri.Host, EnabledSslProtocols = proto, CertificateRevocationCheckMode = SkipRevocation ? System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck : System.Security.Cryptography.X509Certificates.X509RevocationMode.Online };
                    await ssl.AuthenticateAsClientAsync(options, timeoutCts.Token);
#else
                    await ssl.AuthenticateAsClientAsync(uri.Host, null, proto, !SkipRevocation).WaitWithCancellation(timeoutCts.Token);
#endif
                    return ssl.SslProtocol == proto;
                } catch (Exception ex) when (NormalizeProbeException(ex, token, timeoutCts) is TimeoutException) {
                    return false;
                } catch { return false; }
            }
#if NET8_0_OR_GREATER
            SupportsTls13 = await TryHandshake(System.Security.Authentication.SslProtocols.Tls13);
#endif
            SupportsTls12 = await TryHandshake(System.Security.Authentication.SslProtocols.Tls12);
            // Legacy probes (best-effort). We intentionally test legacy protocols to report insecure offerings.
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 obsolete warnings
            SupportsTls11 = await TryHandshake(System.Security.Authentication.SslProtocols.Tls11);
            SupportsTls10 = await TryHandshake(System.Security.Authentication.SslProtocols.Tls);
#pragma warning restore SYSLIB0039
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
