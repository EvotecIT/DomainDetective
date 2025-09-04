using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class RobotsTxtRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[RobotsTxtCodes.Missing] = new RecommendationAdvice {
            Code = RobotsTxtCodes.Missing,
            Title = "robots.txt not found",
            Why = "Some crawlers rely on robots.txt to determine crawl policy.",
            How = "Publish robots.txt over HTTPS at /. Adjust policies as needed.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "crawl" },
            Impact = "Crawlers may crawl indiscriminately.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/robots.txt returns 200."
        };
        map[RobotsTxtCodes.FallbackHttp] = new RecommendationAdvice {
            Code = RobotsTxtCodes.FallbackHttp,
            Title = "robots.txt served over HTTP",
            Why = "Serving robots.txt only over HTTP can break policy enforcement and leaks metadata.",
            How = "Serve robots.txt over HTTPS and redirect HTTP to HTTPS.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "https" },
            Impact = "Policy may be ignored by strict clients.",
            Effort = RecommendationEffort.Low,
            Verify = "HTTPS robots.txt reachable; HTTP redirects to HTTPS."
        };
        map[RobotsTxtCodes.AiBotDirectivesPresent] = new RecommendationAdvice {
            Code = RobotsTxtCodes.AiBotDirectivesPresent,
            Title = "AI bot directives present",
            Why = "Explicit AI crawl directives improve privacy and content governance.",
            How = "Review and maintain up-to-date AI bot directives in robots.txt.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "ai" },
            Impact = "Clearer policy for AI crawlers.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt contains AI user-agent rules."
        };
        map[RobotsTxtCodes.DownloadFailed] = new RecommendationAdvice {
            Code = RobotsTxtCodes.DownloadFailed,
            Title = "robots.txt download failed",
            Why = "Network or server errors prevented retrieving robots.txt.",
            How = "Verify endpoint availability and TLS; ensure reverse-proxy allows access.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "network" },
            Impact = "Crawlers may default to aggressive behavior.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt fetch returns 200 over HTTPS."
        };
        map[RobotsTxtCodes.Available] = new RecommendationAdvice {
            Code = RobotsTxtCodes.Available,
            Title = "robots.txt accessible over HTTPS",
            Why = "Serving robots.txt over HTTPS ensures policies are retrieved securely.",
            How = "Maintain robots.txt at https://<domain>/robots.txt and enforce HTTPS redirects.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "https" },
            Impact = "Crawlers reliably obtain crawl policy.",
            Effort = RecommendationEffort.Low,
            Verify = "GET https://<domain>/robots.txt returns 200."
        };
        map[RobotsTxtCodes.DisallowPresent] = new RecommendationAdvice {
            Code = RobotsTxtCodes.DisallowPresent,
            Title = "Disallow rules defined",
            Why = "Disallow directives restrict crawler access to sensitive paths.",
            How = "Review and update Disallow entries as site structure changes.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "disallow" },
            Impact = "Helps protect areas from unwanted crawling.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt contains Disallow directives."
        };
        map[RobotsTxtCodes.SitemapPresent] = new RecommendationAdvice {
            Code = RobotsTxtCodes.SitemapPresent,
            Title = "Sitemap referenced in robots.txt",
            Why = "Listing sitemaps aids crawlers in discovering site content.",
            How = "Ensure sitemap URLs are accurate and reachable.",
            Domain = RecommendationDomain.Privacy,
            Tags = new [] { "robots", "sitemap" },
            Impact = "Improves crawler coverage of valid URLs.",
            Effort = RecommendationEffort.Low,
            Verify = "robots.txt contains a Sitemap directive pointing to an existing sitemap."
        };
    }
}

