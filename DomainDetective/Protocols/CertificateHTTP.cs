using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;

namespace DomainDetective {
    public class CertificateAnalysis {
        /// <summary>Gets or sets the URL that was checked.</summary>
        public string Url { get; set; }
        /// <summary>Gets or sets a value indicating whether the certificate chain is valid.</summary>
        public bool IsValid { get; set; }
        /// <summary>Gets or sets a value indicating whether the endpoint was reachable.</summary>
        public bool IsReachable { get; set; }
        /// <summary>Gets or sets the number of days until expiry.</summary>
        public int DaysToExpire { get; set; }
        /// <summary>Gets the total validity period in days.</summary>
        public int DaysValid { get; private set; }
        /// <summary>Gets a value indicating whether the certificate has expired.</summary>
        public bool IsExpired { get; private set; }

        /// <summary>Gets the negotiated HTTP protocol version.</summary>
        public Version ProtocolVersion { get; private set; }

        /// <summary>Gets a value indicating HTTP/2 support.</summary>
        public bool Http2Supported { get; private set; }

        /// <summary>Gets a value indicating HTTP/3 support.</summary>
        public bool Http3Supported { get; private set; }

        /// <summary>Gets the leaf certificate.</summary>
        public X509Certificate2 Certificate { get; set; }

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
                        if (response.Version < HttpVersion.Version30) {
                            IsReachable = false;
                            ProtocolVersion = response.Version;
                            logger?.WriteError("HTTP version downgrade for {0}: {1}", url, response.Version);
                            return;
                        }
        public bool SecuresUnrelatedHosts { get; private set; }

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
            using (var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10 }) {
                handler.ServerCertificateCustomValidationCallback = (HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors policyErrors) => {
                    Certificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));
                    Chain.Clear();
                    if (chain != null) {
                        foreach (var element in chain.ChainElements) {
                            Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                        }
                    }
                    IsValid = policyErrors == SslPolicyErrors.None;
                    return IsValid;
                };
                using (var client = new HttpClient(handler)) {
                    try {
#if NET6_0_OR_GREATER
                        var request = new HttpRequestMessage(HttpMethod.Get, url) {
                            Version = HttpVersion.Version30,
                            VersionPolicy = HttpVersionPolicy.RequestVersionExact
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
                                using var ssl = new SslStream(tcp.GetStream(), false, static (_, _, _, errors) => errors == SslPolicyErrors.None);
#if NET5_0_OR_GREATER
                                var authOptions = new SslClientAuthenticationOptions { TargetHost = uri.Host };
                                await ssl.AuthenticateAsClientAsync(authOptions, timeoutCts.Token);
#else
                                await ssl.AuthenticateAsClientAsync(uri.Host).WaitWithCancellation(timeoutCts.Token);
#endif
                                if (ssl.RemoteCertificate is X509Certificate2 cert) {
                                    Certificate = new X509Certificate2(cert.Export(X509ContentType.Cert));
                                    var xchain = new X509Chain();
                                    xchain.Build(cert);
                                    Chain.Clear();
                                    foreach (var element in xchain.ChainElements) {
                                        Chain.Add(new X509Certificate2(element.Certificate.Export(X509ContentType.Cert)));
                                    }
                                }
                            } catch (Exception ex) {
                                logger?.WriteError("Error retrieving certificate for {0}: {1}", url, ex.ToString());
                            }
                        }
                        if (Certificate != null) {
                            DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
                            DaysValid = (int)(Certificate.NotAfter - Certificate.NotBefore).TotalDays;
                            IsExpired = Certificate.NotAfter < DateTime.Now;
                            await QueryRevocationEndpoints(cancellationToken);
                            PopulateSubjectAlternativeNames();
                        }
                    } catch (Exception ex) {
                        IsReachable = false;
                        logger?.WriteError("Exception reaching {0}: {1}", url, ex.ToString());
                    }
                }
            }
        }

        private async Task QueryRevocationEndpoints(CancellationToken cancellationToken) {
            OcspUrls.Clear();
            CrlUrls.Clear();
            OcspRevoked = null;
            CrlRevoked = null;
            try {
                var parser = new X509CertificateParser();
                var bcCert = parser.ReadCertificate(Certificate.RawData);

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
                    var id = new CertificateID(CertificateID.HashSha1, issuer, bcCert.SerialNumber);
                    var gen = new OcspReqGenerator();
                    gen.AddRequest(id);
                    var req = gen.Generate();
                    using var client = new HttpClient();
                    using var content = new ByteArrayContent(req.GetEncoded());
                    content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/ocsp-request");
                    using var resp = await client.PostAsync(OcspUrls[0], content, cancellationToken);
                    if (resp.IsSuccessStatusCode) {
                        var bytes = await resp.Content.ReadAsByteArrayAsync();
                        var ocspResp = new OcspResp(bytes);
                        if (ocspResp.Status == OcspRespStatus.Successful) {
                            var basic = (BasicOcspResp)ocspResp.GetResponseObject();
                            if (basic.Responses.Length > 0) {
                                OcspRevoked = basic.Responses[0].GetCertStatus() is RevokedStatus;
                            }
                        }
                    }
                }

                if (CrlUrls.Count > 0) {
                    using var client = new HttpClient();
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

        /// <summary>
        /// Standalone version to check the website certificate.
        /// </summary>
        /// <param name="url">The URL. If no scheme is provided, "https://" will be prepended.</param>
        /// <param name="port">The port.</param>
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
        /// Analyzes a provided certificate without performing any network operations.
        /// </summary>
        /// <param name="certificate">Certificate instance to inspect.</param>
        /// <param name="cancellationToken">Token used to cancel the operation.</param>
        public async Task AnalyzeCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) {
            Certificate = new X509Certificate2(certificate.RawData);
            var chain = new X509Chain();
            IsValid = chain.Build(certificate);
            Chain.Clear();
            foreach (var element in chain.ChainElements) {
                Chain.Add(new X509Certificate2(element.Certificate.RawData));
            }
            DaysToExpire = (int)(certificate.NotAfter - DateTime.Now).TotalDays;
            DaysValid = (int)(certificate.NotAfter - certificate.NotBefore).TotalDays;
            IsExpired = certificate.NotAfter < DateTime.Now;
            await QueryRevocationEndpoints(cancellationToken);
            PopulateSubjectAlternativeNames();
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
    }

}