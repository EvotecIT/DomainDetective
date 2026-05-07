using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SitemapRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SitemapCodes.Missing] = new RecommendationAdvice {
            Code = SitemapCodes.Missing,
            Title = "Sitemap not found",
            Why = "Sitemaps help crawlers and search engines discover canonical URLs.",
            How = "Publish a sitemap at https://<domain>/sitemap.xml or reference it from robots.txt.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "seo", "crawl" },
            Impact = "Valid pages may be discovered late or inconsistently.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/sitemap.xml returns a valid sitemap XML document."
        };
        map[SitemapCodes.XmlInvalid] = new RecommendationAdvice {
            Code = SitemapCodes.XmlInvalid,
            Title = "Sitemap XML is invalid",
            Why = "Invalid XML can cause crawlers to ignore the sitemap.",
            How = "Fix XML generation, escaping, namespaces, and response encoding.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "xml", "seo" },
            Impact = "Crawler discovery and indexing diagnostics may be unreliable.",
            Effort = RecommendationEffort.Medium,
            Verify = "Parse the sitemap with an XML parser and confirm the root is urlset or sitemapindex."
        };
        map[SitemapCodes.CrossHostSitemap] = new RecommendationAdvice {
            Code = SitemapCodes.CrossHostSitemap,
            Title = "Cross-host sitemap advertised",
            Why = "A site advertising another host's sitemap can mix ownership, stale migrations, and unrelated crawl/indexing failures into this domain's posture.",
            How = "Update robots.txt or sitemap indexes to reference only the current domain's sitemap unless the cross-host relationship is intentional and verified.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "robots", "seo", "ownership" },
            Impact = "Crawlers and diagnostics may follow stale or unrelated sitemap documents and report another site owner's failures against this domain.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt and sitemapindex entries for the domain point to expected sitemap hosts."
        };
        map[SitemapCodes.UrlRedirect] = new RecommendationAdvice {
            Code = SitemapCodes.UrlRedirect,
            Title = "Sitemap URL redirects",
            Why = "Sitemaps should list canonical final URLs instead of redirecting URLs.",
            How = "Update sitemap generation to emit the final canonical URL.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "redirect", "seo" },
            Impact = "Crawlers waste crawl budget and may report indexing exclusions.",
            Effort = RecommendationEffort.Low,
            Verify = "Each sitemap URL returns 2xx without redirecting."
        };
        map[SitemapCodes.UrlRedirectLoop] = new RecommendationAdvice {
            Code = SitemapCodes.UrlRedirectLoop,
            Title = "Sitemap URL has a redirect loop",
            Why = "A redirect loop makes the URL unreachable to crawlers.",
            How = "Fix the web server or CDN redirect rule and remove the URL from the sitemap until it is reachable.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "redirect", "loop", "seo" },
            Impact = "The page cannot be indexed or reliably fetched.",
            Effort = RecommendationEffort.Medium,
            Verify = "Fetching the URL follows redirects to a final 2xx page without repeating a URL."
        };
        map[SitemapCodes.UrlAccessForbidden] = new RecommendationAdvice {
            Code = SitemapCodes.UrlAccessForbidden,
            Title = "Sitemap URL blocks unauthenticated fetches",
            Why = "A URL can exist for a browser session but still return 401/403 to crawler-style requests. Search engines and audit tools may treat that as blocked access.",
            How = "Confirm whether the page should be indexable. If yes, adjust WAF, bot, geo, authentication, or landing-page rules so crawler requests can fetch it.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "403", "access", "crawler", "seo" },
            Impact = "Crawler diagnostics may report blocked by access forbidden even when the page opens for a signed-in or previously cleared browser.",
            Effort = RecommendationEffort.Medium,
            Verify = "Fetch the sitemap URL without browser cookies and confirm it returns 2xx for intended crawlers."
        };
        map[SitemapCodes.UrlClientError] = new RecommendationAdvice {
            Code = SitemapCodes.UrlClientError,
            Title = "Sitemap URL returns a client error",
            Why = "URLs listed in a sitemap should be crawlable canonical pages.",
            How = "Restore the page, fix the URL, or remove the URL from the sitemap.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "4xx", "seo" },
            Impact = "Search engines may report not found or other indexing failures.",
            Effort = RecommendationEffort.Low,
            Verify = "Each sitemap URL returns 2xx for a crawler-like request."
        };
        map[SitemapCodes.UrlNoIndex] = new RecommendationAdvice {
            Code = SitemapCodes.UrlNoIndex,
            Title = "Sitemap URL is marked noindex",
            Why = "A sitemap advertises URLs for crawling, while noindex asks crawlers not to index them.",
            How = "Remove noindex from canonical pages or remove noindex pages from the sitemap.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "noindex", "seo" },
            Impact = "Search Console may report excluded by noindex for sitemap-listed pages.",
            Effort = RecommendationEffort.Low,
            Verify = "Sitemap URLs do not return X-Robots-Tag noindex or meta robots noindex."
        };
        map[SitemapCodes.CanonicalMismatch] = new RecommendationAdvice {
            Code = SitemapCodes.CanonicalMismatch,
            Title = "Sitemap URL canonicalizes elsewhere",
            Why = "Sitemaps should normally contain the canonical URL that should be indexed.",
            How = "Replace the sitemap URL with the page's canonical target or fix the page canonical tag.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "sitemap", "canonical", "seo" },
            Impact = "Search engines may choose an alternate canonical and exclude the sitemap URL.",
            Effort = RecommendationEffort.Low,
            Verify = "The rel=canonical href matches the final sitemap URL."
        };
    }
}
