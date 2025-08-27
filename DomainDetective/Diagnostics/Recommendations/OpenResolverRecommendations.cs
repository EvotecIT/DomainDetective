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
    }
}

