using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class IpNeighborRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[IpNeighborCodes.PassiveDnsQueryFailed] = new RecommendationAdvice {
            Code = IpNeighborCodes.PassiveDnsQueryFailed,
            Title = "Passive DNS query failed",
            Why = "Network/API issues prevented neighbor enumeration.",
            How = "Retry later or from a different network; verify passive DNS provider availability.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "neighbors", "passive-dns" },
            Impact = "Uncertain co-hosting posture.",
            Effort = RecommendationEffort.Low,
            Verify = "Repeat the query; expect a list of co-hosted domains."
        };
        map[IpNeighborCodes.AnalysisFailed] = new RecommendationAdvice {
            Code = IpNeighborCodes.AnalysisFailed,
            Title = "IP neighbor analysis failed",
            Why = "Errors during PTR/passive DNS prevented analysis.",
            How = "Check DNS connectivity and provider access; retry analysis.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "neighbors" },
            Impact = "Visibility gap for shared hosting risks.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run neighbor analysis without errors."
        };
        map[IpNeighborCodes.ExcessiveCoHosts] = new RecommendationAdvice {
            Code = IpNeighborCodes.ExcessiveCoHosts,
            Title = "High number of co-hosted domains",
            Why = "Shared infrastructure with many tenants increases risk and reputation coupling.",
            How = "Consider dedicated IPs for critical services and monitor neighbors for abuse.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "neighbors", "risk" },
            Impact = "Higher likelihood of collateral blacklistings or throttling.",
            Effort = RecommendationEffort.Medium,
            Verify = "Neighbor count reduced or isolated to dedicated IPs."
        };
    }
}

