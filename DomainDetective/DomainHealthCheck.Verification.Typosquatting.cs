using DnsClientX;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective {
    public partial class DomainHealthCheck {
        /// <summary>
        /// Generates typosquatting variants and checks if they resolve.
        /// </summary>
        /// <param name="domainName">Domain to analyze.</param>
        /// <param name="cancellationToken">Token to cancel the operation.</param>
        public async Task VerifyTyposquatting(string domainName, CancellationToken cancellationToken = default) {
            if (string.IsNullOrWhiteSpace(domainName)) {
                throw new ArgumentNullException(nameof(domainName));
            }
            domainName = NormalizeDomain(domainName);
            UpdateIsPublicSuffix(domainName);
            TyposquattingAnalysis.DnsConfiguration = DnsConfiguration;
            TyposquattingAnalysis.LevenshteinThreshold = TyposquattingLevenshteinThreshold;
            TyposquattingAnalysis.DetectHomoglyphs = EnableHomoglyphDetection;
            TyposquattingAnalysis.BrandKeywords.Clear();
            TyposquattingAnalysis.BrandKeywords.AddRange(TyposquattingBrandKeywords);
            TyposquattingAnalysis.EnrichmentOptions.MaxCandidates = TyposquattingEnableEnrichment ? TyposquattingEnrichmentMaxCandidates : 0;
            TyposquattingAnalysis.EnrichmentOptions.MaxParallelism = TyposquattingEnrichmentMaxParallelism;
            TyposquattingAnalysis.EnrichmentOptions.IncludeWhois = TyposquattingEnrichWhois;
            TyposquattingAnalysis.EnrichmentOptions.IncludeHttp = TyposquattingEnrichHttp || TyposquattingEnableContentSimilarity;
            TyposquattingAnalysis.EnrichmentOptions.IncludeIpEnrichment = TyposquattingEnrichIp;
            TyposquattingAnalysis.EnrichmentOptions.IncludeWebStaticScan = TyposquattingEnrichWebStaticScan || (TyposquattingEnableContentSimilarity && TyposquattingSimilarityIncludeWebStaticScan);
            TyposquattingAnalysis.EnrichmentOptions.IncludeThreatIntel = TyposquattingEnrichThreatIntel;
            TyposquattingAnalysis.EnrichmentOptions.CaptureHttpBody = TyposquattingCaptureHttpBody || TyposquattingEnableContentSimilarity;
            TyposquattingAnalysis.EnrichmentOptions.GoogleSafeBrowsingApiKey = GoogleSafeBrowsingApiKey;
            TyposquattingAnalysis.EnrichmentOptions.PhishTankApiKey = PhishTankApiKey;
            TyposquattingAnalysis.EnrichmentOptions.VirusTotalApiKey = VirusTotalApiKey;
            TyposquattingAnalysis.OwnershipProfileOptions.Enabled = TyposquattingCompareOwnershipSignals;
            TyposquattingAnalysis.OwnershipProfileOptions.IncludeWhois = TyposquattingOwnershipIncludeWhois;
            TyposquattingAnalysis.OwnershipProfileOptions.IncludeIpEnrichment = TyposquattingOwnershipIncludeIp;
            TyposquattingAnalysis.ContentSimilarityOptions.Enabled = TyposquattingEnableContentSimilarity;
            TyposquattingAnalysis.ContentSimilarityOptions.IncludeWebStaticScan = TyposquattingSimilarityIncludeWebStaticScan;
            TyposquattingAnalysis.VisualSimilarityOptions.Enabled = TyposquattingEnableVisualSimilarity;
            TyposquattingAnalysis.VisualSimilarityOptions.MaxCandidates = TyposquattingVisualMaxCandidates;
            TyposquattingAnalysis.VisualSimilarityOptions.MaxParallelism = TyposquattingVisualMaxParallelism;
            TyposquattingAnalysis.VisualSimilarityOptions.EnableStaticAssetCapture = TyposquattingVisualUseStaticAssetCapture;
            TyposquattingAnalysis.VisualSimilarityOptions.MaxAssetBytes = TyposquattingVisualMaxAssetBytes;
            TyposquattingAnalysis.VisualSimilarityOptions.MaxAssetsPerPage = TyposquattingVisualMaxAssetsPerPage;
            await TyposquattingAnalysis.Analyze(domainName, _logger, cancellationToken);
        }
    }
}
