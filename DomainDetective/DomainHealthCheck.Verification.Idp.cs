using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective
{
    public partial class DomainHealthCheck
    {
        /// <summary>
        /// Probes OIDC discovery and GetUserRealm to collect tenant hints.
        /// </summary>
        public Task VerifyIdpInfo(string domain, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.IDENTITYPROVIDER, () => VerifyIdpInfoDirectCore(domain, cancellationToken));

        private async Task VerifyIdpInfoDirectCore(string domain, CancellationToken cancellationToken = default)
        {
            IdpInfoAnalysis = new IdpInfoAnalysis {
                HttpClientFactory = HttpClientFactory
            };
            await IdpInfoAnalysis.AnalyzeAsync(domain, _logger, cancellationToken);
        }
    }
}
