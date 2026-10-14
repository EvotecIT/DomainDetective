using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Queries random subdomains to detect wildcard DNS behavior.
        /// </summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="sampleCount">Number of names to test.</param>
        public Task VerifyWildcardDns(string domainName, int sampleCount = 3) => VerifyWildcardDns(domainName, sampleCount, CancellationToken.None);

        /// <summary>Queries wildcard DNS with caller cancellation.</summary>
        /// <param name="domainName">Domain to verify.</param>
        /// <param name="sampleCount">Number of names at each tested depth.</param>
        /// <param name="cancellationToken">Token canceling discovery and samples.</param>
        public async Task VerifyWildcardDns(string domainName, int sampleCount, CancellationToken cancellationToken) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            WildcardDnsAnalysis.DnsConfiguration = DnsConfiguration;
            await WildcardDnsAnalysis.Analyze(domainName, _logger, sampleCount, cancellationToken);
        }
    }
}
