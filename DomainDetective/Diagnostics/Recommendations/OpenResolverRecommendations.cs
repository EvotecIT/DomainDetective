using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class OpenResolverRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[OpenResolverCodes.RecursionDetected] = new RecommendationAdvice {
            Code = OpenResolverCodes.RecursionDetected,
            Title = "Disable recursion on authoritative DNS servers",
            Why = "Open recursion increases attack surface and enables cache poisoning or abuse.",
            How = "Configure authoritative servers with 'recursion no;' or equivalent and restrict to internal resolvers if needed.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "security", "recursion" },
            Impact = "Potential amplification abuse and data leakage.",
            Effort = RecommendationEffort.Low,
            Verify = "Queries for unrelated domains return REFUSED and RA bit is not set."
        };
        map[OpenResolverCodes.RecursionClosed] = new RecommendationAdvice {
            Code = OpenResolverCodes.RecursionClosed,
            Title = "Recursive queries denied",
            Why = "Server refuses recursion from arbitrary clients, reducing amplification risk.",
            How = "No action required; maintain current recursion restrictions.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "recursion" },
            Impact = "Prevents reflection and cache-poisoning abuse.",
            Effort = RecommendationEffort.Low,
            Verify = "Queries for unrelated domains return REFUSED and RA bit is unset."
        };
        map[OpenResolverCodes.CheckFailed] = new RecommendationAdvice {
            Code = OpenResolverCodes.CheckFailed,
            Title = "Open resolver test failed",
            Why = "Timeouts or errors during checks may hide real risks.",
            How = "Verify DNS reachability and retry from a known-good vantage point.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "recursion" },
            Impact = "Uncertain posture; manual validation required.",
            Effort = RecommendationEffort.Low,
            Verify = "Repeat the test and confirm server response codes."
        };
        map[OpenResolverCodes.AnomalousResponse] = new RecommendationAdvice {
            Code = OpenResolverCodes.AnomalousResponse,
            Title = "Anomalous response to recursion probe",
            Why = "Unexpected flags/rcodes can indicate caching proxies, rate limiting, or DNS manipulation. No confirmed open recursion was detected.",
            How = "Review authoritative DNS server configuration and any upstream proxies/firewalls; ensure recursion is disabled and responses are consistent.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "recursion", "anomaly" },
            Impact = "Potential troubleshooting and visibility gap; may hide misconfiguration.",
            Effort = RecommendationEffort.Medium,
            Verify = "Repeat the recursion probe across networks; expect REFUSED/no recursion and stable flags."
        };
    }
}

