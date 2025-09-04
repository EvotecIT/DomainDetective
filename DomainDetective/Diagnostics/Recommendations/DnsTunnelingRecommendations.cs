using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsTunnelingRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DnsTunnelingCodes.SuspiciousLabel] = new RecommendationAdvice {
            Code = DnsTunnelingCodes.SuspiciousLabel,
            Title = "Suspicious long/encoded DNS label detected",
            Why = "Very long or encoded labels can indicate data exfiltration via DNS tunneling.",
            How = "Investigate the source, enable DNS logging, and block suspicious domains at the resolver.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dns", "tunneling", "exfiltration" },
            Impact = "Potential data leakage through DNS queries.",
            Effort = RecommendationEffort.Medium,
            Verify = "No further suspicious labels observed after mitigation."
        };
        map[DnsTunnelingCodes.HighFrequency] = new RecommendationAdvice {
            Code = DnsTunnelingCodes.HighFrequency,
            Title = "High DNS query frequency observed",
            Why = "Burst patterns are consistent with tunneling or DGA activity.",
            How = "Rate-limit at the resolver, analyze clients for malware, and block offending FQDNs.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dns", "rate", "tunneling" },
            Impact = "Potential malware presence and data exfiltration.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query volumes return to baseline after containment."
        };
        map[DnsTunnelingCodes.NoIndicators] = new RecommendationAdvice {
            Code = DnsTunnelingCodes.NoIndicators,
            Title = "No tunneling indicators detected",
            Why = "DNS query patterns appear normal without signs of tunneling or exfiltration.",
            How = "Maintain logging and monitoring to detect future anomalies.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dns", "tunneling", "monitoring" },
        };
    }
}

