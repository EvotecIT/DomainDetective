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

        if (!string.Equals(IdpInfoAnalysis.Domain, domainName, StringComparison.OrdinalIgnoreCase) ||
            (!IdpInfoAnalysis.DiscoverySucceeded && !IdpInfoAnalysis.GetUserRealmSucceeded)) {
            await VerifyIdpInfo(domainName, cancellationToken).ConfigureAwait(false);
        }

        if (!string.Equals(DnsInventoryAnalysis.Subject, domainName, StringComparison.OrdinalIgnoreCase) ||
            (!DnsInventoryAnalysis.QuerySucceeded && DnsInventoryAnalysis.TotalRecords == 0)) {
            await VerifyDnsInventoryAsync(domainName, cancellationToken).ConfigureAwait(false);
        }

        if (!string.Equals(SubdomainsAnalysis.Subject, domainName, StringComparison.OrdinalIgnoreCase) ||
            (!SubdomainsAnalysis.QuerySucceeded && (SubdomainsAnalysis.Subdomains?.Count ?? 0) == 0)) {
            await VerifySubdomainsAsync(domainName, cancellationToken).ConfigureAwait(false);
        }

        if (!string.Equals(AutodiscoverAnalysis.Subject, domainName, StringComparison.OrdinalIgnoreCase)) {
            await VerifyAutodiscover(domainName, cancellationToken).ConfigureAwait(false);
        }

        if (!string.Equals(DKIMAnalysis.Subject, domainName, StringComparison.OrdinalIgnoreCase)) {
            await VerifyDKIM(domainName, Array.Empty<string>(), cancellationToken).ConfigureAwait(false);
        }

        Microsoft365TenantAnalysis = new Microsoft365TenantAnalysis();
        Microsoft365TenantAnalysis.Analyze(
            domainName,
            IdpInfoAnalysis,
            DnsInventoryAnalysis,
            DKIMAnalysis,
            SubdomainsAnalysis,
            AutodiscoverAnalysis,
            _logger);

        await Microsoft365TenantAnalysis.ProbeAuthenticationAsync(
            domainName,
            HttpClientFactory,
            _logger,
            cancellationToken).ConfigureAwait(false);
    }
}
