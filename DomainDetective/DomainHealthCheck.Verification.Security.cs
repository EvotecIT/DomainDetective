using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        private async Task VerifySecurityTxtAsync(string domainName, CancellationToken cancellationToken) {
            SecurityTXTAnalysis = new SecurityTXTAnalysis();
            await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger);
        }

        private Task VerifyHpkpAsync(string domainName, CancellationToken cancellationToken) {
            return HPKPAnalysis.AnalyzeUrl($"http://{domainName}", _logger);
        }

        private async Task VerifyDnsTtlAsync(string domainName, CancellationToken cancellationToken) {
            await DnsTtlAnalysis.Analyze(domainName, _logger);
            await DnsTtlAnalysis.AnalyzeUniformityAcrossServers(domainName, _logger, cancellationToken);
        }

        private Task VerifyFlatteningServiceAsync(string domainName, CancellationToken cancellationToken) {
            FlatteningServiceAnalysis = new FlatteningServiceAnalysis { DnsConfiguration = DnsConfiguration };
            return FlatteningServiceAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
