using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    /// Captures a lightweight DNS inventory for a domain by querying common record types
    /// and recording answers (and optionally authority/additional sections).
    /// </summary>
    public async Task VerifyDnsInventoryAsync(string domainName, CancellationToken cancellationToken = default)
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

        await DnsInventoryAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken).ConfigureAwait(false);
    }
}

