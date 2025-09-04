using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class FlatteningServiceRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[FlatteningServiceCodes.UsesFlatteningService] = new RecommendationAdvice {
            Code = FlatteningServiceCodes.UsesFlatteningService,
            Title = "CNAME points to a flattening service",
            Why = "Flattening services may mask target changes and introduce provider coupling or TTL nuances at the apex.",
            How = "Ensure provider-recommended setup (A/AAAA at apex via flattening), monitor target ownership, and document failover plans.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "cname", "flattening", "cloudflare" },
            Impact = "Operational coupling and misrouting risk on provider changes.",
            Effort = RecommendationEffort.Low,
            Verify = "Resolve apex and confirm addresses align with intended provider behavior."
        };

        map[FlatteningServiceCodes.ResolvedAddresses] = new RecommendationAdvice {
            Code = FlatteningServiceCodes.ResolvedAddresses,
            Title = "flattening service returns addresses",
            Why = "Provider flattening supplies A/AAAA records at the apex for seamless aliasing.",
            How = "Document provider dependency and monitor for address changes.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "cname", "flattening" },
            Impact = "Simplifies apex alias management.",
            Effort = RecommendationEffort.Low,
            Verify = "Resolve apex and observe provider-managed addresses."
        };
    }
}

