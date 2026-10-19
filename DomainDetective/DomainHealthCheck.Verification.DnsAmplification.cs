using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective
{
    public partial class DomainHealthCheck
    {
        /// <summary>
        /// Evaluates DNS amplification posture for authoritative name servers (recursion + EDNS + response size probes).
        /// </summary>
        public Task VerifyDnsAmplification(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.DNSAMPLIFICATION, () => VerifyDnsAmplificationDirectCore(domainName, cancellationToken));

        private async Task VerifyDnsAmplificationDirectCore(string domainName, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
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

            await DnsAmplificationAnalysis.Analyze(domainName, _logger, cancellationToken).ConfigureAwait(false);
        }
    }
}

