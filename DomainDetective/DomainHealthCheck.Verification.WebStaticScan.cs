using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Performs a static (non-browser) web scan for the specified URL using shared components.
        /// </summary>
        public async Task VerifyWebStaticScan(string url, CancellationToken cancellationToken = default)
        {
            WebStaticScanAnalysis = new WebStaticScanAnalysis
            {
                DnsConfiguration = DnsConfiguration,
                GetRegistrableDomain = _publicSuffixList != null ? new System.Func<string, string>(_publicSuffixList.GetRegistrableDomain) : null
            };
            await WebStaticScanAnalysis.Analyze(url, _logger, cancellationToken);
        }
    }
}
