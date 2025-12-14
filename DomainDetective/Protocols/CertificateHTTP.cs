using System;
using System.Collections.Generic;
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
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using DnsClientX;

namespace DomainDetective {
    /// <summary>
    /// Represents certificate validation results for an HTTP endpoint.
    /// </summary>
    /// <para>Part of the DomainDetective project.</para>
    /// <remarks>
    /// Validation includes hostname matching and chain verification using the
    /// system trust store.
    /// </remarks>
    public class CertificateAnalysis : IHasAssessments {
        public string? Subject { get; set; }
        /// <summary>Gets or sets the URL that was checked.</summary>
        public string Url { get; set; } = string.Empty;
        /// <summary>Gets or sets a value indicating whether the certificate chain is valid.</summary>
        public bool IsValid { get; set; }
        /// <summary>Gets or sets a value indicating whether the endpoint was reachable.</summary>
        public bool IsReachable { get; set; }
        /// <summary>Gets whether the certificate matches the requested host.</summary>
        public bool HostnameMatch { get; private set; }
        /// <summary>Gets or sets the number of days until expiry.</summary>
        public int DaysToExpire { get; set; }
        /// <summary>Gets the total validity period in days.</summary>
        public int DaysValid { get; private set; }
        /// <summary>Gets a value indicating whether the certificate has expired.</summary>
        public bool IsExpired { get; private set; }

        /// <summary>Gets the negotiated HTTP protocol version.</summary>
        public Version? ProtocolVersion { get; private set; }

        /// <summary>Gets a value indicating HTTP/2 support.</summary>
        public bool Http2Supported { get; private set; }

        /// <summary>Gets a value indicating HTTP/3 support.</summary>
        public bool Http3Supported { get; private set; }

        /// <summary>Gets the leaf certificate.</summary>
        public X509Certificate2? Certificate { get; set; }

        /// <summary>Gets the certificate chain.</summary>
        public List<X509Certificate2> Chain { get; } = new();
        /// <summary>Gets OCSP endpoints from the certificate.</summary>
        public List<string> OcspUrls { get; } = new();
        /// <summary>Gets CRL endpoints from the certificate.</summary>
        public List<string> CrlUrls { get; } = new();
        /// <summary>Gets a value indicating whether the certificate is revoked according to OCSP.</summary>
        public bool? OcspRevoked { get; private set; }
        /// <summary>Gets a value indicating whether the certificate is revoked according to CRL.</summary>
        public bool? CrlRevoked { get; private set; }
        /// <summary>Gets or sets the HTTP request timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);
        /// <summary>Gets DNS names listed in the certificate subject alternative name extension.</summary>
        public List<string> SubjectAlternativeNames { get; } = new();
        /// <summary>Gets wildcard entries with matching subdomains.</summary>
        public Dictionary<string, List<string>> WildcardSubdomains { get; } = new();
        /// <summary>Gets a value indicating whether the certificate contains wildcard names.</summary>
        public bool IsWildcardCertificate { get; private set; }
        /// <summary>Gets a value indicating the certificate secures multiple unrelated hosts.</summary>
        public bool SecuresUnrelatedHosts { get; private set; }
        /// <summary>Gets a value indicating whether the certificate is self-signed.</summary>
        public bool IsSelfSigned { get; private set; }
        /// <summary>Gets the public key algorithm.</summary>
        public string KeyAlgorithm { get; private set; } = string.Empty;
        /// <summary>Gets the key size in bits.</summary>
        public int KeySize { get; private set; }
        /// <summary>Indicates if the certificate uses a key under 2048 bits.</summary>
        public bool WeakKey { get; private set; }
        /// <summary>Indicates if the certificate is signed with SHA-1.</summary>
        public bool Sha1Signature { get; private set; }
        /// <summary>Indicates if the certificate uses RSA-PSS for its signature.</summary>
        public bool RsaPssSignature { get; private set; }
        /// <summary>Gets the negotiated TLS protocol when <see cref="CaptureTlsDetails"/> is true.</summary>
        public SslProtocols TlsProtocol { get; private set; }
        /// <summary>Indicates if TLS 1.3 was negotiated.</summary>
        public bool Tls13Used { get; private set; }
        /// <summary>Gets the negotiated cipher algorithm.</summary>
        public CipherAlgorithmType CipherAlgorithm { get; private set; }
        /// <summary>Gets the cipher strength.</summary>
        public int CipherStrength { get; private set; }
        /// <summary>Gets the negotiated cipher suite name.</summary>
        public string CipherSuite { get; private set; } = string.Empty;
        /// <summary>Gets the Diffie-Hellman key size, if used.</summary>
        public int DhKeyBits { get; private set; }
        /// <summary>Enable gathering TLS protocol and cipher information.</summary>
        public bool CaptureTlsDetails { get; set; }
        /// <summary>Skip certificate revocation checks.</summary>
        public bool SkipRevocation { get; set; }
        /// <summary>Gets a value indicating whether the certificate is present in public CT logs.</summary>
        public bool PresentInCtLogs { get; private set; }

        /// <summary>Collection of CT log entries retrieved for the certificate.</summary>
        public IReadOnlyList<JsonElement> CtLogEntries => _ctLogEntries;

        /// <summary>Optional override to retrieve CT log data for testing.</summary>
        public Func<string, Task<string>>? CtLogQueryOverride { private get; set; }

        /// <summary>CT log API templates. Each entry should contain a {0} placeholder for the SHA-256 fingerprint.</summary>
        public List<string> CtLogApiTemplates => _ctLogAggregator.ApiTemplates;

        private readonly List<JsonElement> _ctLogEntries = new();
        private readonly CtLogAggregator _ctLogAggregator = new();

        /// <summary>Structured assessments captured during certificate checks.</summary>
        public List<Assessment> Assessments { get; } = new();

        /// <summary>Coarse web TLS grade.</summary>
        public GradeLevel GradeLevel { get; private set; } = GradeLevel.Unknown;
        /// <summary>Indicates legacy TLS protocol negotiated.</summary>
        public bool LegacyEnabled { get; private set; }
        /// <summary>Indicates if server supports TLS 1.0 during handshake probe.</summary>
        public bool SupportsTls10 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.1 during handshake probe.</summary>
        public bool SupportsTls11 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.2 during handshake probe.</summary>
        public bool SupportsTls12 { get; private set; }
        /// <summary>Indicates if server supports TLS 1.3 during handshake probe.</summary>
        public bool SupportsTls13 { get; private set; }
        /// <summary>Count of embedded SCTs in the certificate.</summary>
        public int SctCount { get; private set; }
        /// <summary>Indicates whether the certificate includes TLS Feature (OCSP Must-Staple).</summary>
        public bool OcspMustStaple { get; private set; }
        /// <summary>Indicates whether the server stapled an OCSP response during handshake (best-effort, via OpenSSL probe).</summary>
        public bool? OcspStaplingPresent { get; private set; }

        internal CtLogAggregator CtLogs => _ctLogAggregator;

        internal static IEnumerable<string> ExtractMxHosts(IEnumerable<DnsAnswer> records)
        {
            foreach (DnsAnswer record in records)
            {
                string data = record.Data ?? record.DataRaw;
                if (string.IsNullOrWhiteSpace(data))
                {
                    continue;
                }

                string[] parts = data.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    string host = parts[1].Trim('.');
                    if (!string.IsNullOrWhiteSpace(host))
                    {
                        yield return host;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the certificate from the specified HTTPS endpoint.
        /// </summary>
        /// <param name="url">URL to query.</param>
        /// <param name="port">Port number to use.</param>
        /// <param name="logger">Logger instance for diagnostics.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeUrl(string url, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            var builder = new UriBuilder(url) { Port = port };
            url = builder.ToString();
            Url = url;
            IsSelfSigned = false;
            using var _collector = AssessmentCollector.ForAnalysis(logger, this, category: "CERT", target: url);
            using (var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10, CheckCertificateRevocationList = !SkipRevocation }) {
#if NET8_0_OR_GREATER
                handler.SslProtocols = SslProtocols.Tls13 | SslProtocols.Tls12;
#endif
                handler.ServerCertificateCustomValidationCallback = (HttpRequestMessage requestMessage, X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors policyErrors) => {
                    if (certificate == null) {
                        return false;
                    }
                    Certificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));
                    Chain.Clear();
                    if (chain != null) {
                        foreach (var element in chain.ChainElements) {
                            Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                        }
                    }
                    IsSelfSigned = Chain.Count == 1;
                    IsValid = policyErrors == SslPolicyErrors.None;
                    HostnameMatch = (policyErrors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                    return IsValid;
                };
                using (var client = new HttpClient(handler)) {
                    try {
#if NET6_0_OR_GREATER
                        var request = new HttpRequestMessage(HttpMethod.Get, url) {
                            Version = HttpVersion.Version30,
                            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                        };
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        IsReachable = response.IsSuccessStatusCode;
                        if (IsReachable) {
                            ProtocolVersion = response.Version;
                            Http3Supported = response.Version >= HttpVersion.Version30;
                            Http2Supported = response.Version >= HttpVersion.Version20;
                        }
#else
                        var request = new HttpRequestMessage(HttpMethod.Get, url);
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        IsReachable = response.IsSuccessStatusCode;
                        if (IsReachable) {
                            ProtocolVersion = response.Version;
                            Http2Supported = response.Version.Major >= 2;
                            Http3Supported = false;
                        }
#endif
                        if (Certificate == null && Http3Supported) {
                            try {
                                var uri = new Uri(url);
                                using var tcp = new TcpClient();
                                using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                                timeoutCts.CancelAfter(Timeout);
#if NET6_0_OR_GREATER
                                await tcp.ConnectAsync(uri.Host, port, timeoutCts.Token);
#else
                                await tcp.ConnectAsync(uri.Host, port).WaitWithCancellation(timeoutCts.Token);
#endif
                                using var ssl = new SslStream(tcp.GetStream(), false, (sender, certificate, chain, errors) => {
                                    HostnameMatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                                    return errors == SslPolicyErrors.None;
                                });
#if NET5_0_OR_GREATER
                                var authOptions = new SslClientAuthenticationOptions { TargetHost = uri.Host };
                                authOptions.CertificateRevocationCheckMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
                                await ssl.AuthenticateAsClientAsync(authOptions, timeoutCts.Token);
#else
                                await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.None, !SkipRevocation).WaitWithCancellation(timeoutCts.Token);
#endif
                                if (ssl.RemoteCertificate is X509Certificate2 cert) {
                                    Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
                                    var xchain = new X509Chain();
                                    xchain.Build(cert);
                                    Chain.Clear();
                                    foreach (var element in xchain.ChainElements) {
                                        Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                                    }
                                    IsSelfSigned = Chain.Count == 1;
                                }
                            } catch (Exception ex) {
                                logger.WriteErrorCode(CertificateHttpCodes.FetchFailed, "Error retrieving certificate for {0}: {1}", url, ex.ToString());
                            }
                        }
                        if (Certificate != null) {
                            PopulateKeyInfo();
                            if (CaptureTlsDetails) {
                                await PopulateTlsInfo(new Uri(url), port, cancellationToken);
                            }
                            DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
                            DaysValid = (int)(Certificate.NotAfter - Certificate.NotBefore).TotalDays;
                            IsExpired = Certificate.NotAfter < DateTime.Now;
                            if (!SkipRevocation) {
                                await QueryRevocationEndpoints(cancellationToken);
                            }
                            PopulateSubjectAlternativeNames();
                            PopulateSctAndTlsFeature(logger);
                            await ProbeProtocolSupport(new Uri(url), port, logger, cancellationToken);
                            await ProbeOcspStaplingWithOpenSsl(new Uri(url), port, logger, cancellationToken);
                            await QueryCtLogs(cancellationToken);
                            // Compute grade once we have basic data (and optional TLS details)
                            ComputeGrade(logger);
                        }
                    } catch (Exception ex) {
                        IsReachable = false;
                        logger.WriteErrorCode(CertificateHttpCodes.ConnectFailed, "Exception reaching {0}: {1}", url, ex.ToString());
                    }
                }
            }
        }

        private async Task QueryRevocationEndpoints(CancellationToken cancellationToken) {
            if (SkipRevocation) {
                return;
            }
            OcspUrls.Clear();
            CrlUrls.Clear();
            OcspRevoked = null;
            CrlRevoked = null;
            try {
                var certificate = Certificate;
                if (certificate == null) {
                    return;
                }
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(certificate.RawData);

                var aiaExt = bcCert.GetExtensionValue(X509Extensions.AuthorityInfoAccess);
                if (aiaExt != null) {
                    var seq = (Asn1Sequence)Asn1Object.FromByteArray(aiaExt.GetOctets());
                    foreach (var obj in seq) {
                        var ad = AccessDescription.GetInstance(obj);
                        if (ad.AccessMethod.Equals(new DerObjectIdentifier("1.3.6.1.5.5.7.48.1"))) {
                            var name = GeneralName.GetInstance(ad.AccessLocation.ToAsn1Object());
                            if (name.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(name.Name).GetString();
                                OcspUrls.Add(uri);
                            }
                        }
                    }
                }

                var crlExt = bcCert.GetExtensionValue(X509Extensions.CrlDistributionPoints);
                if (crlExt != null) {
                    var cdp = CrlDistPoint.GetInstance(Asn1Object.FromByteArray(crlExt.GetOctets()));
                    foreach (var dp in cdp.GetDistributionPoints()) {
                        var names = dp.DistributionPointName?.Name as GeneralNames;
                        if (names == null) {
                            continue;
                        }
                        foreach (var gn in names.GetNames()) {
                            if (gn.TagNo == GeneralName.UniformResourceIdentifier) {
                                var uri = DerIA5String.GetInstance(gn.Name).GetString();
                                CrlUrls.Add(uri);
                            }
                        }
                    }
                }

                if (OcspUrls.Count > 0 && Chain.Count > 1) {
                    var issuer = parser.ReadCertificate(Chain[1].RawData);
#pragma warning disable CS0618
                    var id = new CertificateID(CertificateID.HashSha1, issuer, bcCert.SerialNumber);
#pragma warning restore CS0618
                    var gen = new OcspReqGenerator();
                    gen.AddRequest(id);
                    var req = gen.Generate();
                    var client = SharedHttpClient.Instance;
                    using var content = new ByteArrayContent(req.GetEncoded());
                    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
                    using var resp = await client.PostAsync(OcspUrls[0], content, cancellationToken);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await resp.Content.ReadAsByteArrayAsync();
                        OcspRevoked = ParseOcspResponse(bytes);
                    }
                }

                if (CrlUrls.Count > 0) {
                    var client = SharedHttpClient.Instance;
                    using var resp = await client.GetAsync(CrlUrls[0], cancellationToken);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await resp.Content.ReadAsByteArrayAsync();
                        var crl = new X509CrlParser().ReadCrl(bytes);
                        CrlRevoked = crl.IsRevoked(bcCert);
                    }
                }
            } catch {
                // ignore revocation failures
            }
        }

        /// <summary>Parses an OCSP response and returns the revocation status.</summary>
        /// <param name="response">OCSP response bytes.</param>
        /// <returns><c>true</c> if revoked, <c>false</c> if valid, <c>null</c> if inconclusive.</returns>
        internal static bool? ParseOcspResponse(byte[] response) {
            var ocspResp = new OcspResp(response);
            if (ocspResp.Status != OcspRespStatus.Successful) {
                return null;
            }

            var basic = (BasicOcspResp)ocspResp.GetResponseObject();
            if (basic.Responses.Length == 0) {
                return null;
            }

            var status = basic.Responses[0].GetCertStatus();
            return status switch {
                RevokedStatus => true,
                UnknownStatus => null,
                _ => false
            };
        }

        private async Task QueryCtLogs(CancellationToken cancellationToken)
        {
            PresentInCtLogs = false;
            _ctLogEntries.Clear();
            if (Certificate == null)
            {
                return;
            }
            byte[] hashBytes;
#if NET5_0_OR_GREATER
            hashBytes = Certificate.GetCertHash(HashAlgorithmName.SHA256);
#else
            using (var sha = SHA256.Create()) {
                hashBytes = sha.ComputeHash(Certificate.RawData);
            }
#endif
            var fingerprint = BitConverter.ToString(hashBytes).Replace("-", string.Empty).ToLowerInvariant();

            _ctLogAggregator.ApiTemplates.Clear();
            _ctLogAggregator.ApiTemplates.AddRange(CtLogApiTemplates);
            _ctLogAggregator.QueryOverride = CtLogQueryOverride;

            var entries = await _ctLogAggregator.QueryAsync(fingerprint, cancellationToken).ConfigureAwait(false);
            _ctLogEntries.AddRange(entries);
            PresentInCtLogs = _ctLogEntries.Count > 0;
        }

        /// <summary>
        /// Standalone version to check the website certificate.
        /// </summary>
        /// <param name="url">The URL. If no scheme is provided, "https://" will be prepended.</param>
        /// <param name="port">The port.</param>
        /// <param name="cancellationToken">Cancellation token to stop the operation.</param>
        /// <returns>The populated <see cref="CertificateAnalysis"/> instance.</returns>
        public static async Task<CertificateAnalysis> CheckWebsiteCertificate(string url, int port = 443, CancellationToken cancellationToken = default) {
            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
                url = $"https://{url}";
            }
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl(url, port, new InternalLogger(), cancellationToken);
            return analysis;
        }

        /// <summary>
        /// Checks certificates for multiple URLs concurrently.
        /// </summary>
        /// <param name="urls">The URLs. If no scheme is provided, "https://" will be prepended.</param>
        /// <param name="port">The port.</param>
        /// <param name="cancellationToken">Cancellation token to stop the operation.</param>
        /// <returns>List of populated <see cref="CertificateAnalysis"/> instances.</returns>
        public static async Task<IReadOnlyList<CertificateAnalysis>> CheckWebsiteCertificates(IEnumerable<string> urls, int port = 443, CancellationToken cancellationToken = default) {
            var tasks = urls.Select(u => CheckWebsiteCertificate(u, port, cancellationToken));
            return await Task.WhenAll(tasks).ConfigureAwait(false);
        }

        /// <summary>
        /// Analyzes a provided certificate without performing any network operations.
        /// </summary>
        /// <param name="certificate">Certificate instance to inspect.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) {
            Certificate = new X509Certificate2(certificate.RawData);
            IsSelfSigned = false;
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = SkipRevocation ? X509RevocationMode.NoCheck : X509RevocationMode.Online;
            IsValid = chain.Build(certificate);
            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(new X509Certificate2(element.Certificate.RawData));
            }
            IsSelfSigned = Chain.Count == 1;
            PopulateKeyInfo();
            DaysToExpire = (int)(certificate.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(certificate.NotAfter - certificate.NotBefore).TotalDays;
            IsExpired = certificate.NotAfter < DateTime.Now;
            if (!SkipRevocation) {
                await QueryRevocationEndpoints(cancellationToken);
            }
            PopulateSubjectAlternativeNames();
            await QueryCtLogs(cancellationToken);
        }

        private void PopulateSubjectAlternativeNames() {
            SubjectAlternativeNames.Clear();
            WildcardSubdomains.Clear();
            IsWildcardCertificate = false;
            SecuresUnrelatedHosts = false;

            if (Certificate == null) {
                return;
            }

            var parser = new X509CertificateParser();
            var bcCert = parser.ReadCertificate(Certificate.RawData);
            var sanExt = bcCert.GetExtensionValue(X509Extensions.SubjectAlternativeName);
            if (sanExt != null) {
                var names = GeneralNames.GetInstance(Asn1Object.FromByteArray(sanExt.GetOctets()));
                foreach (var gn in names.GetNames()) {
                    if (gn.TagNo == GeneralName.DnsName) {
                        var dns = DerIA5String.GetInstance(gn.Name).GetString();
                        SubjectAlternativeNames.Add(dns);
                    }
                }
            }

            var cn = Certificate.GetNameInfo(X509NameType.DnsName, false);
            if (!string.IsNullOrWhiteSpace(cn) && !SubjectAlternativeNames.Contains(cn)) {
                SubjectAlternativeNames.Add(cn);
            }

            var wildcards = new List<string>();
            foreach (var name in SubjectAlternativeNames) {
                if (name.StartsWith("*.", StringComparison.Ordinal)) {
                    wildcards.Add(name);
                }
            }

            foreach (var wc in wildcards) {
                var baseDomain = wc.Substring(2);
                var matches = new List<string>();
                foreach (var n in SubjectAlternativeNames) {
                    if (!n.Equals(wc, StringComparison.OrdinalIgnoreCase) && n.EndsWith('.' + baseDomain, StringComparison.OrdinalIgnoreCase)) {
                        if (!matches.Contains(n)) {
                            matches.Add(n);
                        }
                    }
                }
                WildcardSubdomains[wc] = matches;
            }

            IsWildcardCertificate = WildcardSubdomains.Count > 0;

            var baseDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in SubjectAlternativeNames) {
                var parts = name.Split('.');
                if (parts.Length >= 2) {
                    var baseDom = parts[parts.Length - 2] + "." + parts[parts.Length - 1];
                    baseDomains.Add(baseDom);
                } else {
                    baseDomains.Add(name);
                }
            }
            SecuresUnrelatedHosts = baseDomains.Count > 1 && SubjectAlternativeNames.Count > 5;
        }

        private void PopulateKeyInfo() {
            var certificate = Certificate;
            if (certificate == null) {
                return;
            }
            KeyAlgorithm = certificate.PublicKey?.Oid?.FriendlyName ?? certificate.PublicKey?.Oid?.Value ?? string.Empty;
            try {
                // PublicKey.Key is obsolete in modern runtimes; prefer algorithm-specific helpers.
#if NET6_0_OR_GREATER
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
            WeakKey = KeySize > 0 && KeySize < 2048;
            var oid = certificate.SignatureAlgorithm?.Value ?? string.Empty;
            Sha1Signature = oid == "1.2.840.113549.1.1.5" ||
                            oid == "1.2.840.10040.4.3" ||
                            oid == "1.3.14.3.2.29";
            RsaPssSignature = oid == "1.2.840.113549.1.1.10";
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
#if NET6_0_OR_GREATER
                await tcp.ConnectAsync(p.Host, p.Port, token);
#else
                await tcp.ConnectAsync(p.Host, p.Port).WaitWithCancellation(token);
#endif
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
#if NET6_0_OR_GREATER
                await tcp.ConnectAsync(host, port, token);
#else
                await tcp.ConnectAsync(host, port).WaitWithCancellation(token);
#endif
            }
            return tcp;
        }
#pragma warning restore CA2000

        private async Task PopulateTlsInfo(Uri uri, int port, CancellationToken token) {
            using var tcp = await ConnectWithProxy(uri.Host, port, token);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(token);
            timeoutCts.CancelAfter(Timeout);
            using var ssl = new SslStream(tcp.GetStream(), false, static (_, _, _, _) => true);
#if NET8_0_OR_GREATER
            await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.Tls13 | SslProtocols.Tls12, !SkipRevocation)
                .WaitWithCancellation(timeoutCts.Token);
#else
            await ssl.AuthenticateAsClientAsync(uri.Host, null, SslProtocols.None, !SkipRevocation).WaitWithCancellation(timeoutCts.Token);
#endif
            TlsProtocol = ssl.SslProtocol;
#if NET8_0_OR_GREATER
            Tls13Used = ssl.SslProtocol == SslProtocols.Tls13;
#else
            Tls13Used = (int)ssl.SslProtocol == 12288;
#endif
            CipherAlgorithm = ssl.CipherAlgorithm;
            CipherStrength = ssl.CipherStrength;
#if NET6_0_OR_GREATER
            CipherSuite = ssl.NegotiatedCipherSuite.ToString();
#endif
            if (ssl.KeyExchangeAlgorithm == ExchangeAlgorithmType.DiffieHellman) {
                DhKeyBits = ssl.KeyExchangeStrength;
            }
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

        private async Task ProbeProtocolSupport(Uri uri, int port, InternalLogger logger, CancellationToken token)
        {
            SupportsTls10 = false; SupportsTls11 = false; SupportsTls12 = false; SupportsTls13 = false;
            async Task<bool> TryHandshake(System.Security.Authentication.SslProtocols proto)
            {
                try {
                    using var tcp = await ConnectWithProxy(uri.Host, port, token);
                    using var ssl = new System.Net.Security.SslStream(tcp.GetStream(), false, static (_, _, _, _) => true);
#if NET5_0_OR_GREATER
                    var options = new System.Net.Security.SslClientAuthenticationOptions { TargetHost = uri.Host, EnabledSslProtocols = proto, CertificateRevocationCheckMode = SkipRevocation ? System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck : System.Security.Cryptography.X509Certificates.X509RevocationMode.Online };
                    await ssl.AuthenticateAsClientAsync(options, token);
#else
                    await ssl.AuthenticateAsClientAsync(uri.Host, null, proto, !SkipRevocation).WaitWithCancellation(token);
#endif
                    return ssl.SslProtocol == proto;
                } catch { return false; }
            }
#if NET5_0_OR_GREATER
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
