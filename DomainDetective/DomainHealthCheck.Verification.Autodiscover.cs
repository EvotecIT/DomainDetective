using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries Autodiscover related records for a domain.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyAutodiscover(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            AutodiscoverAnalysis = new AutodiscoverAnalysis {
                DnsConfiguration = DnsConfiguration
            };
            await AutodiscoverAnalysis.Analyze(domainName, DnsConfiguration, _logger, cancellationToken);
            AutodiscoverHttpAnalysis = new AutodiscoverHttpAnalysis();
            await AutodiscoverHttpAnalysis.Analyze(domainName, _logger, cancellationToken);
            AutodiscoverAnalysis.SetHttpEndpoints(AutodiscoverHttpAnalysis.Endpoints);
        }
    }
}
