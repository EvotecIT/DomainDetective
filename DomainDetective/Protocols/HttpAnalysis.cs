using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading.Tasks;

namespace DomainDetective {
    public class HttpAnalysis {
        public int? StatusCode { get; private set; }
        public TimeSpan ResponseTime { get; private set; }
        public bool HstsPresent { get; private set; }
        public bool IsReachable { get; private set; }
        public int MaxRedirects { get; set; } = 10;

        public async Task AnalyzeUrl(string url, bool checkHsts, InternalLogger logger) {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = MaxRedirects };
            using var client = new HttpClient(handler);
            var sw = Stopwatch.StartNew();
            try {
                var response = await client.GetAsync(url);
                sw.Stop();
                StatusCode = (int)response.StatusCode;
                ResponseTime = sw.Elapsed;
                IsReachable = true;
                if (checkHsts) {
                    HstsPresent = response.Headers.Contains("Strict-Transport-Security");
                }
            } catch (Exception ex) {
                sw.Stop();
                IsReachable = false;
                logger?.WriteError("HTTP check failed for {0}: {1}", url, ex.Message);
            }
        }

        public static async Task<HttpAnalysis> CheckUrl(string url, bool checkHsts = false) {
            var analysis = new HttpAnalysis();
            await analysis.AnalyzeUrl(url, checkHsts, new InternalLogger());
            return analysis;
        }
    }
}
