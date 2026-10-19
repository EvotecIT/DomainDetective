using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Detects dangling CNAME records for the domain.
        /// </summary>
        public Task VerifyDanglingCname(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.DANGLINGCNAME, () => VerifyDanglingCnameDirectCore(domainName, cancellationToken));

        private async Task VerifyDanglingCnameDirectCore(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            DanglingCnameAnalysis = new DanglingCnameAnalysis { DnsConfiguration = DnsConfiguration };
            await DanglingCnameAnalysis.Analyze(domainName, _logger, cancellationToken);
        }

        /// <summary>
        /// Checks for CNAMEs pointing to takeover prone providers.
        /// </summary>
        public async Task VerifyTakeoverCname(string domainName, CancellationToken cancellationToken = default) {
            domainName = NormalizeDomain(domainName);
            TakeoverCnameAnalysis = new TakeoverCnameAnalysis { DnsConfiguration = DnsConfiguration };
            await TakeoverCnameAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
