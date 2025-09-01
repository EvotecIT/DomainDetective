using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsblRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DnsblCodes.Listed] = new RecommendationAdvice {
            Code = DnsblCodes.Listed,
            Title = "Address/domain listed on DNSBL",
            Why = "Listings indicate potential abuse or misconfiguration impacting delivery and reputation.",
            How = "Investigate abuse, secure services, and follow the provider's delisting procedure.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dnsbl", "abuse", "reputation" },
            Impact = "Mail delivery may be rejected or throttled; reputation degraded.",
            Effort = RecommendationEffort.Medium,
            Verify = "Recheck listing status; ensure provider returns NXDOMAIN/not listed."
        };
        map[DnsblCodes.QueryFailed] = new RecommendationAdvice {
            Code = DnsblCodes.QueryFailed,
            Title = "DNSBL query failed",
            Why = "Network or resolver issues prevented DNSBL checks, hiding real risks.",
            How = "Verify DNS/UDP reachability and retry from a stable resolver.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dnsbl", "network" },
            Impact = "Uncertain blacklist posture.",
            Effort = RecommendationEffort.Low,
            Verify = "Run checks again; expect successful responses (listed or not)."
        };
        map[DnsblCodes.ProviderTimeout] = new RecommendationAdvice {
            Code = DnsblCodes.ProviderTimeout,
            Title = "DNSBL provider timed out",
            Why = "Provider outage or filtering can cause timeouts.",
            How = "Retry later or test from another network; consider alternate providers.",
            Domain = RecommendationDomain.ThreatIntel,
            Tags = new [] { "dnsbl", "timeout" },
            Impact = "Partial coverage of DNSBL checks.",
            Effort = RecommendationEffort.Low,
            Verify = "Subsequent queries succeed within normal latency."
        };
    }
}

