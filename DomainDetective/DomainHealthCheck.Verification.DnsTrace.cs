using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    /// Captures an iterative, authoritative-style DNS trace (root to answer) with a hop-by-hop log.
    /// </summary>
    public async Task VerifyDnsTraceAsync(string domainName, CancellationToken cancellationToken = default)
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

        await DnsTraceAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken).ConfigureAwait(false);
    }
}

