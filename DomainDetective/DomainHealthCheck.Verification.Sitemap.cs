using System.Threading;
using System.Threading.Tasks;

namespace DomainDetective;

public partial class DomainHealthCheck {
    /// <summary>
    /// Validates sitemap XML and sitemap-listed URLs for the specified domain or URL.
    /// </summary>
    /// <param name="domainName">Domain, host, sitemap URL, or HTTP/HTTPS URL to analyze.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    public async Task VerifySitemapAsync(string domainName, CancellationToken cancellationToken = default) {
        var previous = SitemapAnalysis;
        SitemapAnalysis = new SitemapAnalysis {
            HttpHandlerFactory = previous.HttpHandlerFactory
        };
        await SitemapAnalysis.AnalyzeAsync(domainName, _logger, cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
