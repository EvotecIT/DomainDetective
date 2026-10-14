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
            Title = "No matching SNMP response observed",
            Why = "No response to public probes can result from disabled SNMP, access controls, packet loss or an unreachable target; it does not prove the service is secured.",
            How = "Verify SNMP configuration and network reachability before concluding that access is restricted.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "snmp", "network" },
            Impact = "Exposure remains unconfirmed from this probe alone.",
            Effort = RecommendationEffort.Low,
            Verify = "Probes using default community strings receive no response."
        };
    }
}

