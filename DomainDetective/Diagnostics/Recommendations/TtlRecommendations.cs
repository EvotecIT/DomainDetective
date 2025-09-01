using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class TtlRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TtlCodes.TooShortForDnssec] = new RecommendationAdvice {
            Code = TtlCodes.TooShortForDnssec,
            Title = "Increase TTL for DNSSEC-signed zones",
            Why = "Very low TTLs increase validation load and can cause frequent cache misses in signed zones.",
            How = "Prefer TTLs ≥ 3600 seconds for A/AAAA/MX/NS/SOA when DNSSEC is enabled; adjust to your change cadence.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "dnssec", "ttl" }
        };

        map[TtlCodes.TooShort] = new RecommendationAdvice {
            Code = TtlCodes.TooShort,
            Title = "Raise DNS TTL to reduce churn",
            Why = "Very short TTLs increase resolver traffic and can degrade performance.",
            How = "Use TTLs ≥ 300 seconds for steady-state; lower temporarily during planned changes only.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.TooLong] = new RecommendationAdvice {
            Code = TtlCodes.TooLong,
            Title = "Lower excessive DNS TTLs",
            Why = "Excessive TTLs delay propagation of necessary changes and incident response.",
            How = "Target TTLs ≤ 86400 seconds for typical records; shorten when frequent changes are expected.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.A_AAAA_Mismatch] = new RecommendationAdvice {
            Code = TtlCodes.A_AAAA_Mismatch,
            Title = "Align A and AAAA TTLs",
            Why = "Large TTL differences between A and AAAA can cause inconsistent client behavior.",
            How = "Set similar TTLs for A and AAAA records to ensure consistent caching.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };
    }
}

