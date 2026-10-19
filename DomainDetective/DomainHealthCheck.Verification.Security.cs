using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>Executes the verify security txt operation.</summary>
        public Task VerifySecurityTxt(string domainName, CancellationToken cancellationToken = default) =>
            CompleteDirectCheckAsync(HealthCheckType.SECURITYTXT, () => VerifySecurityTxtDirectCore(domainName, cancellationToken), cancellationToken, ownerDomain: domainName);

        private async Task VerifySecurityTxtDirectCore(string domainName, CancellationToken cancellationToken = default) {
            SecurityTXTAnalysis = new SecurityTXTAnalysis();
            await SecurityTXTAnalysis.AnalyzeSecurityTxtRecord(domainName, _logger, cancellationToken: cancellationToken);
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

            // The value and cross-server matrices own distinct result collections.
            // Start value initialization first, then overlap their network phases and
            // observe both before publishing the TTL check's completion.
            var values = DnsTtlAnalysis.Analyze(domainName, _logger, cancellationToken);
            if (DnsConfiguration.ResolverMaxConcurrency == 1 || DnsConfiguration.MultiResolverMaxParallelism == 1) {
                // A caller choosing one resolver slot retains foreground value
                // collection before best-effort cross-server reachability work.
                await values.ConfigureAwait(false);
                await DnsTtlAnalysis.AnalyzeUniformityAcrossServers(domainName, _logger, cancellationToken).ConfigureAwait(false);
                return;
            }
            var uniformity = DnsTtlAnalysis.AnalyzeUniformityAcrossServers(domainName, _logger, cancellationToken);
            await Task.WhenAll(values, uniformity).ConfigureAwait(false);
        }

        private Task VerifyFlatteningServiceAsync(string domainName, CancellationToken cancellationToken) {
            FlatteningServiceAnalysis = new FlatteningServiceAnalysis { DnsConfiguration = DnsConfiguration };
            return FlatteningServiceAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
