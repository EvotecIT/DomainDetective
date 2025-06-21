using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace DomainDetective {
    public class CertificateAnalysis {
        public string Url { get; set; }
        public bool IsValid { get; set; }
        public bool IsReachable { get; set; }
        public int DaysToExpire { get; set; }

        public Version ProtocolVersion { get; private set; }

        public X509Certificate2 Certificate { get; set; }

        public async Task AnalyzeUrl(string url, int port, InternalLogger logger) {
            var builder = new UriBuilder(url) { Port = port };
            url = builder.ToString();
            using (var handler = new HttpClientHandler()) {
                handler.ServerCertificateCustomValidationCallback = (HttpRequestMessage requestMessage, X509Certificate2 certificate, X509Chain chain, SslPolicyErrors policyErrors) => {
                    Certificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));
                    return true;
                };
                using (var client = new HttpClient(handler)) {
                    try {
                        var request = new HttpRequestMessage(HttpMethod.Get, url) {
                            Version = new Version(2, 0)
                        };
                        HttpResponseMessage response = await client.SendAsync(request);
                        ProtocolVersion = response.Version;
                        IsReachable = response.IsSuccessStatusCode;
                        if (Certificate != null) {
                            DaysToExpire = (int)(Certificate.NotAfter - DateTime.Now).TotalDays;
                        }
                    } catch (Exception ex) {
                        IsReachable = false;
                        logger?.WriteError("Exception reaching {0}: {1}", url, ex.Message);
                    }
                }
            }
        }

        /// <summary>
        /// Standalone version to check the website certificate.
        /// </summary>
        /// <param name="url">The URL.</param>
        /// <param name="port">The port.</param>
        /// <returns></returns>
        public static async Task<CertificateAnalysis> CheckWebsiteCertificate(string url, int port = 443) {
            var analysis = new CertificateAnalysis();
            await analysis.AnalyzeUrl(url, port, new InternalLogger());
            return analysis;
        }
    }

}