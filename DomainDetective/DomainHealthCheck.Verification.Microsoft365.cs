using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>
    /// Builds a Microsoft 365 aggregate view by reusing identity, DNS inventory, subdomain, and Autodiscover analyses.
    /// </summary>
    public async Task VerifyMicrosoft365TenantAsync(string domainName, CancellationToken cancellationToken = default) {
        if (string.IsNullOrWhiteSpace(domainName)) {
            throw new ArgumentNullException(nameof(domainName));
        }

        domainName = NormalizeDomain(domainName);
        UpdateIsPublicSuffix(domainName);
        if (IsPublicSuffix) {
            return;
        }

        await CollectMicrosoft365SignalsAsync(domainName, cancellationToken).ConfigureAwait(false);

        Microsoft365TenantAnalysis = new Microsoft365TenantAnalysis();
        Microsoft365TenantAnalysis.Analyze(
            domainName,
            IdpInfoAnalysis,
            DnsInventoryAnalysis,
            DKIMAnalysis,
            SubdomainsAnalysis,
            AutodiscoverAnalysis,
            _logger);

        await RunAdmittedCheckAsync(() => Microsoft365TenantAnalysis.ProbeAuthenticationAsync(
            domainName,
            HttpClientFactory,
            _logger,
            cancellationToken), cancellationToken, "Microsoft365Authentication").ConfigureAwait(false);
    }
}
