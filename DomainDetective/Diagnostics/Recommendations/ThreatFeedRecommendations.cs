using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ThreatFeedRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[ThreatFeedCodes.NoListings] = new RecommendationAdvice
        {
            Code = ThreatFeedCodes.NoListings,
            Title = "No threat feed listings detected",
            Why = "None of the checked IP reputation feeds flag the address, indicating a clean reputation.",
            How = "Maintain good security practices and monitor feeds regularly.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new[] { "reputation" }
        };
    }
}
