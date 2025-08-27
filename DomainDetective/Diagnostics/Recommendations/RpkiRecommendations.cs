using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class RpkiRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[RpkiCodes.QueryFailed] = new RecommendationAdvice {
            Code = RpkiCodes.QueryFailed,
            Title = "RPKI validation query failed",
            Why = "Network/API errors prevented validation of route origin authorization.",
            How = "Retry later; ensure outbound HTTPS to RIPE stat (or your chosen RPKI source) and consider local cache/mirroring.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rpki", "routing" },
            Impact = "Uncertain routing origin validation.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run RPKI checks and confirm valid/invalid status is returned."
        };
    }
}

