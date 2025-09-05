using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SnmpRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SnmpCodes.Responds] = new RecommendationAdvice {
            Code = SnmpCodes.Responds,
            Title = "Restrict or disable SNMP access",
            Why = "Unauthenticated SNMP responses can expose network details and enable reflection attacks.",
            How = "Disable SNMP on public interfaces or require authentication via SNMPv3 with strong credentials.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "snmp", "network" },
            Impact = "Information disclosure and potential DDoS amplification.",
            Effort = RecommendationEffort.Low,
            Verify = "Probes using default community strings receive no response."
        };
        map[SnmpCodes.Disabled] = new RecommendationAdvice {
            Code = SnmpCodes.Disabled,
            Title = "SNMP disabled or secured",
            Why = "No response to public probes indicates reduced attack surface.",
            How = "No action required; continue monitoring to ensure access remains restricted.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "snmp", "network" },
            Impact = "Limits information disclosure and reflection abuse.",
            Effort = RecommendationEffort.Low,
            Verify = "Probes using default community strings receive no response."
        };
    }
}

