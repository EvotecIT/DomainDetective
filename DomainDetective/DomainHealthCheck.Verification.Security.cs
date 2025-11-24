using System.Threading;
using System.Threading.Tasks;
using System.Linq;

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
            // Provide DKIM selectors discovered earlier (if any)
            try {
                if (DKIMAnalysis?.AnalysisResults != null && DKIMAnalysis.AnalysisResults.Count > 0) {
                    DnsTtlAnalysis.DkimSelectors = DKIMAnalysis.AnalysisResults.Keys.ToList();
                }
            } catch { /* best effort */ }

            DnsTtlAnalysis.CollectAuthoritativeTtls = CollectAuthoritativeTtls;
            await DnsTtlAnalysis.Analyze(domainName, _logger);
            await DnsTtlAnalysis.AnalyzeUniformityAcrossServers(domainName, _logger, cancellationToken);

            // If authoritative DKIM TTLs were gathered, push them into DKIM analysis results for display.
            try
            {
                if (CollectAuthoritativeTtls &&
                    DKIMAnalysis?.AnalysisResults != null &&
                    DKIMAnalysis.AnalysisResults.Count > 0 &&
                    DnsTtlAnalysis.AuthoritativeDkimTxtTtls != null &&
                    DnsTtlAnalysis.AuthoritativeDkimTxtTtls.Count > 0)
                {
                    foreach (var kv in DKIMAnalysis.AnalysisResults)
                    {
                        var selector = kv.Key;
                        var result = kv.Value;
                        var name = !string.IsNullOrWhiteSpace(result.Name)
                            ? result.Name
                            : $"{selector}._domainkey.{domainName}";
                        if (name != null && DnsTtlAnalysis.AuthoritativeDkimTxtTtls.TryGetValue(name, out var ttls) && ttls != null && ttls.Count > 0)
                        {
                            result.AuthoritativeTtls = ttls;
                        }
                    }
                }
            }
            catch { /* non-fatal */ }
        }

        private Task VerifyFlatteningServiceAsync(string domainName, CancellationToken cancellationToken) {
            FlatteningServiceAnalysis = new FlatteningServiceAnalysis { DnsConfiguration = DnsConfiguration };
            return FlatteningServiceAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
