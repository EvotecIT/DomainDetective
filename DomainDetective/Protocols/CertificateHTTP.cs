using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Sockets;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public class CertificateAnalysis {
        public string Url { get; set; }
        public bool IsValid { get; set; }
        public bool IsReachable { get; set; }
        public int DaysToExpire { get; set; }

        public Version ProtocolVersion { get; private set; }

        public bool Http2Supported { get; private set; }

        public bool Http3Supported { get; private set; }

        public X509Certificate2 Certificate { get; set; }

        public List<X509Certificate2> Chain { get; } = new();

        public async Task AnalyzeUrl(string url, int port, InternalLogger logger, CancellationToken cancellationToken = default) {
            var builder = new UriBuilder(url) { Port = port };
            url = builder.ToString();
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
                    return true;
                };
                using (var client = new HttpClient(handler)) {
                    try {
#if NET6_0_OR_GREATER
                        var request = new HttpRequestMessage(HttpMethod.Get, url) {
                            Version = HttpVersion.Version30,
                            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
                        };
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        ProtocolVersion = response.Version;
                        Http3Supported = response.Version >= HttpVersion.Version30;
                        Http2Supported = response.Version >= HttpVersion.Version20;
#else
                        var request = new HttpRequestMessage(HttpMethod.Get, url);
                        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
                        ProtocolVersion = response.Version;
                        Http2Supported = response.Version.Major >= 2;
                        Http3Supported = false;
#endif
                        IsReachable = response.IsSuccessStatusCode;
                        if (Certificate == null && Http3Supported) {
                            try {
                                var uri = new Uri(url);
                                using var tcp = new TcpClient();
                                await tcp.ConnectAsync(uri.Host, port);
                                using var ssl = new SslStream(tcp.GetStream(), false, static (_, _, _, _) => true);
                                await ssl.AuthenticateAsClientAsync(uri.Host);
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
        /// <returns></returns>
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