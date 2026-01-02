using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck
{
    /// <summary>
    /// Builds a certificate transparency (CT) timeline for the specified domain.
    /// </summary>
    public async Task VerifyCtTimelineAsync(string domainName, CancellationToken cancellationToken = default)
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

        await CtTimelineAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken).ConfigureAwait(false);
    }
}

