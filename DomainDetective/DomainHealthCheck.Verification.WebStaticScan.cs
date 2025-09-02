using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Performs a static (non-browser) web scan for the specified URL using shared components.
        /// </summary>
        public async Task VerifyWebStaticScan(string url, CancellationToken cancellationToken = default)
        {
            var prev = WebStaticScanAnalysis;
            var ws = new WebStaticScanAnalysis
            {
                DnsConfiguration = DnsConfiguration,
                GetRegistrableDomain = _publicSuffixList != null ? new System.Func<string, string>(_publicSuffixList.GetRegistrableDomain) : null
            };
            if (prev != null)
            {
                ws.Timeout = prev.Timeout;
                ws.MaxResources = prev.MaxResources;
                ws.Concurrency = prev.Concurrency;
                ws.DiscoveryConcurrency = prev.DiscoveryConcurrency;
                ws.CssConcurrency = prev.CssConcurrency;
                ws.TlsConcurrency = prev.TlsConcurrency;
                ws.DnsConcurrency = prev.DnsConcurrency;
                ws.RespectRobots = prev.RespectRobots;
                ws.EnableThreatIntel = prev.EnableThreatIntel;
                ws.MaxResourcesPerHost = prev.MaxResourcesPerHost;
                ws.TechRulesPath = prev.TechRulesPath;
                ws.SkipThirdParty = prev.SkipThirdParty;
            }
            WebStaticScanAnalysis = ws;
            await WebStaticScanAnalysis.Analyze(url, _logger, cancellationToken);
        }
    }
}
