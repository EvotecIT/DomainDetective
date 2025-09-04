using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class IpNeighborRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[IpNeighborCodes.ExcessiveCoHosts] = new RecommendationAdvice {
            Code = IpNeighborCodes.ExcessiveCoHosts,
            Title = "High co-tenancy observed on web IP",
            Why = "Hundreds of unrelated domains on the same IP indicate shared hosting; performance and reputation may vary.",
            How = "Consider dedicated hosting or segregating critical services to dedicated IPs.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "ip", "neighbors", "shared-hosting" }
        };

        map[IpNeighborCodes.MailOnSharedIp] = new RecommendationAdvice {
            Code = IpNeighborCodes.MailOnSharedIp,
            Title = "Mail IP appears heavily shared",
            Why = "Shared mail infrastructure can inherit reputation from other tenants and increase risk of blocks.",
            How = "Move outbound/inbound MX to dedicated IPs or reputable providers with strict abuse controls.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "ip", "neighbors", "mail" }
        };

        map[IpNeighborCodes.NoMaliciousNeighbors] = new RecommendationAdvice {
            Code = IpNeighborCodes.NoMaliciousNeighbors,
            Title = "No malicious neighbors detected",
            Why = "Passive DNS and PTR checks did not reveal suspicious co-hosted domains.",
            How = "No action required.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "ip", "neighbors" }
        };
    }
}

