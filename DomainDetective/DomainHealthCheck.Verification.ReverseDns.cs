using DnsClientX;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private async Task VerifyReverseDnsAsync(string domainName, CancellationToken cancellationToken) {
            var mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var rdnsHosts = CertificateAnalysis.ExtractMxHosts(mxRecords);
            ReverseDnsAnalysis.Subject = domainName;
            await ReverseDnsAnalysis.AnalyzeHosts(rdnsHosts, _logger);
        }

        private async Task VerifyFcrDnsAsync(string domainName, CancellationToken cancellationToken) {
            var mxRecords = await DnsConfiguration.QueryDNS(domainName, DnsRecordType.MX, cancellationToken: cancellationToken);
            var rdnsHosts = CertificateAnalysis.ExtractMxHosts(mxRecords);
            ReverseDnsAnalysis.Subject = domainName;
            await ReverseDnsAnalysis.AnalyzeHosts(rdnsHosts, _logger);
            FcrDnsAnalysis.Subject = domainName;
            await FcrDnsAnalysis.Analyze(ReverseDnsAnalysis.Results, _logger);
        }
    }
}
