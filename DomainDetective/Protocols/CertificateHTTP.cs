using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

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
        /// <summary>Gets or sets the HTTP request timeout.</summary>
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(30);

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
                                using var ssl = new SslStream(tcp.GetStream(), false, static (_, _, _, errors) => errors == SslPolicyErrors.None);
                                await ssl.AuthenticateAsClientAsync(uri.Host).WaitWithCancellation(timeoutCts.Token);
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
                        }
                    } catch (Exception ex) {
                        IsReachable = false;
                        logger?.WriteError("Exception reaching {0}: {1}", url, ex.ToString());
                    }
                }
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
    }

}