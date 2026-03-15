using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        public async Task VerifySecurityTxt(string domainName, CancellationToken cancellationToken = default) {
            SecurityTXTAnalysis = new SecurityTXTAnalysis();
            await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger);
        }

        private Task VerifyHpkpAsync(string domainName, CancellationToken cancellationToken) {
            return HPKPAnalysis.AnalyzeUrl($"http://{domainName}", _logger);
        }

        private async Task VerifyDnsTtlAsync(string domainName, CancellationToken cancellationToken) {
            // Provide DKIM selectors discovered earlier (if any)
            try {
                if (DKIMAnalysis?.AnalysisResults != null && DKIMAnalysis.AnalysisResults.Count > 0) {
                    DnsTtlAnalysis.DkimSelectors = DKIMAnalysis.AnalysisResults.Keys.ToList();
                }
            } catch { /* best effort */ }

            await DnsTtlAnalysis.Analyze(domainName, _logger);
            await DnsTtlAnalysis.AnalyzeUniformityAcrossServers(domainName, _logger, cancellationToken);
        }

        private Task VerifyFlatteningServiceAsync(string domainName, CancellationToken cancellationToken) {
            FlatteningServiceAnalysis = new FlatteningServiceAnalysis { DnsConfiguration = DnsConfiguration };
            return FlatteningServiceAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
