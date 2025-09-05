using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SpfFlattenedRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SpfCodes.FlattenedIpSetOptimized] = new RecommendationAdvice {
            Code = SpfCodes.FlattenedIpSetOptimized,
            Title = "Flattened SPF IP set optimized",
            Why = "No duplicate addresses were found after flattening, producing a minimal IP set that reduces DNS lookups.",
            How = "Regenerate flattened IPs regularly and monitor include targets so the set remains minimal.",
            Domain = RecommendationDomain.Spf,
            Tags = new [] { "spf", "flattening" },
            Impact = "Keeps SPF fast to evaluate and under lookup limits.",
            Effort = RecommendationEffort.Low,
            Verify = "Flatten SPF IPs again and confirm duplicates are absent."
        };
    }
}
