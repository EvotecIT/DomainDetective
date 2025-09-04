using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class WildcardRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[WildcardCodes.Enabled] = new RecommendationAdvice {
            Code = WildcardCodes.Enabled,
            Title = "Wildcard DNS detected",
            Why = "Wildcard DNS can hide configuration errors and enable phishing/subdomain takeover patterns.",
            How = "Avoid catch-all A/AAAA records; publish explicit hosts or use HTTP 404 handling instead.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "wildcard" }
        };

        map[WildcardCodes.NotDetected] = new RecommendationAdvice {
            Code = WildcardCodes.NotDetected,
            Title = "No wildcard DNS detected",
            Why = "Explicit DNS records prevent shadow subdomains and simplify troubleshooting.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "wildcard" }
        };
    }
}

