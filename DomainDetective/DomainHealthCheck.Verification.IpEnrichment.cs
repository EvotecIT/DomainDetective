using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    /// Enriches discovered IPs (apex, MX, NS) with reverse DNS, ASN/org and geo hints.
    /// </summary>
    public async Task VerifyIpEnrichmentAsync(string domainName, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(domainName))
        {
            throw new ArgumentNullException(nameof(domainName));
        }

        domainName = NormalizeDomain(domainName);
        UpdateIsPublicSuffix(domainName);
        if (IsPublicSuffix)
        {
            return;
        }

        await IpEnrichmentAnalysis.AnalyzeAsync(domainName, additionalIpAddresses: null, logger: _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}

