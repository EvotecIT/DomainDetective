using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class RpkiRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[RpkiCodes.ValidRoa] = new RecommendationAdvice {
            Code = RpkiCodes.ValidRoa,
            Title = "ROA valid for origin ASN",
            Why = "A valid route origin authorization confirms the announced prefix is authorised for this ASN.",
            How = "Maintain ROAs in RPKI repositories for all announced prefixes and monitor their expiry.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rpki", "roa" },
            Impact = "Improves resistance to BGP hijacking.",
            Effort = RecommendationEffort.Low,
            Verify = "Check ROA status with a validator or RIPE Stat."
        };

        map[RpkiCodes.PrefixCovered] = new RecommendationAdvice {
            Code = RpkiCodes.PrefixCovered,
            Title = "Prefix covered by ROA",
            Why = "Covering prefixes ensure each routed address range is authorised in RPKI.",
            How = "Publish ROAs for every originated prefix with the correct ASN and prefix length.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rpki", "routing" },
            Impact = "Reduces risk of unauthorised sub-prefix announcements.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm each prefix is listed in validator output."
        };

        map[RpkiCodes.QueryFailed] = new RecommendationAdvice {
            Code = RpkiCodes.QueryFailed,
            Title = "RPKI validation query failed",
            Why = "Network/API errors prevented validation of route origin authorization.",
            How = "Retry later; ensure outbound HTTPS to RIPE stat (or your chosen RPKI source) and consider local cache/mirroring.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rpki", "routing" },
            Impact = "Uncertain routing origin validation.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run RPKI checks and confirm valid/invalid status is returned."
        };

        map[RpkiCodes.AllValid] = new RecommendationAdvice {
            Code = RpkiCodes.AllValid,
            Title = "All ROAs valid for domain IPs",
            Why = "End-to-end ROA coverage for every apex IP reduces BGP hijack risk.",
            How = "Keep ROAs current for all originated prefixes; monitor expiry and maxLength settings.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rpki", "roa", "routing" },
            Impact = "Maximum protection against invalid origin announcements.",
            Effort = RecommendationEffort.Low,
            Verify = "Validator reports 'valid' for each apex IP's origin prefix/ASN."
        };
    }
}

