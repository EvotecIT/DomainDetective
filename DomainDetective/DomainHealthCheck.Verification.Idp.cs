using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective
{
    public partial class DomainHealthCheck
    {
        /// <summary>
        /// Probes OIDC discovery and GetUserRealm to collect tenant hints.
        /// </summary>
        public async Task VerifyIdpInfo(string domain, CancellationToken cancellationToken = default)
        {
            IdpInfoAnalysis = new IdpInfoAnalysis();
            await IdpInfoAnalysis.AnalyzeAsync(domain, _logger, cancellationToken);
        }
    }
}

