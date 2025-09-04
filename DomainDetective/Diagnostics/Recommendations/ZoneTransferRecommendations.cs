using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ZoneTransferRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ZoneTransferCodes.Allowed] = new RecommendationAdvice {
            Code = ZoneTransferCodes.Allowed,
            Title = "Block unauthenticated zone transfers (AXFR)",
            Why = "Allowing AXFR exposes full zone data and eases reconnaissance.",
            How = "Restrict AXFR to authorized secondaries via TSIG/ACL or disable entirely.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "axfr", "security" },
            Impact = "Information disclosure risk.",
            Effort = RecommendationEffort.Low,
            Verify = "AXFR from untrusted hosts returns REFUSED or FAIL."
        };
        map[ZoneTransferCodes.Restricted] = new RecommendationAdvice {
            Code = ZoneTransferCodes.Restricted,
            Title = "Zone transfers restricted",
            Why = "All tested servers refused unauthenticated AXFR, limiting exposure of zone data.",
            How = "Maintain ACLs or TSIG keys to keep zone transfers limited to authorized secondaries.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "axfr", "security" },
            Impact = "Reduces reconnaissance surface.",
            Effort = RecommendationEffort.Low,
            Verify = "AXFR from untrusted hosts returns REFUSED." 
        };
        map[ZoneTransferCodes.CheckFailed] = new RecommendationAdvice {
            Code = ZoneTransferCodes.CheckFailed,
            Title = "Zone transfer check failed",
            Why = "Connectivity or protocol errors prevented verification.",
            How = "Confirm TCP/53 reachability and server health; retry from a stable vantage point.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "axfr" },
            Impact = "Uncertain posture; re-run checks.",
            Effort = RecommendationEffort.Low,
            Verify = "Attempt AXFR again; expect refusal for unauthorized sources."
        };
    }
}

