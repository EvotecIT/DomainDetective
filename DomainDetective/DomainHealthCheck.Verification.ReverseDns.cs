using DnsClientX;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private Task VerifyReverseDnsAsync(string domainName, CancellationToken cancellationToken)
            => EnsureReverseDnsAsync(domainName, cancellationToken);

        private async Task VerifyReverseDnsInternal(string domainName, CancellationToken cancellationToken) {
            var mxRecords = await GetMxRecordsAsync(domainName, cancellationToken);
            var rdnsHosts = CertificateAnalysis.ExtractMxHosts(mxRecords);
            ReverseDnsAnalysis.Subject = domainName;
            await ReverseDnsAnalysis.AnalyzeHosts(rdnsHosts, _logger);
        }

        private async Task VerifyFcrDnsAsync(string domainName, CancellationToken cancellationToken) {
            await EnsureReverseDnsAsync(domainName, cancellationToken);
            FcrDnsAnalysis.Subject = domainName;
            await FcrDnsAnalysis.Analyze(ReverseDnsAnalysis.Results, _logger);
        }
    }
}
