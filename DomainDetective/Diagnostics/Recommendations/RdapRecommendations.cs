using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class RdapRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[RdapCodes.NotFound] = new RecommendationAdvice {
            Code = RdapCodes.NotFound,
            Title = "RDAP record not found",
            Why = "Domain may be unregistered or the RDAP endpoint unavailable.",
            How = "Confirm domain spelling, check WHOIS, and retry RDAP later.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdap" },
            Impact = "Uncertain registration status.",
            Effort = RecommendationEffort.Low,
            Verify = "RDAP returns domain object with status and events."
        };
        map[RdapCodes.StatusHold] = new RecommendationAdvice {
            Code = RdapCodes.StatusHold,
            Title = "Domain on client/server hold",
            Why = "Hold status can suspend DNS publication due to billing/abuse/transfer.",
            How = "Resolve with registrar; clear hold before production changes.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdap", "status" },
            Impact = "Potential service disruption.",
            Effort = RecommendationEffort.Medium,
            Verify = "RDAP status no longer includes *Hold."
        };
        map[RdapCodes.ExpirySoon] = new RecommendationAdvice {
            Code = RdapCodes.ExpirySoon,
            Title = "Renew domain before RDAP expiry",
            Why = "Imminent RDAP expiry indicates lifecycle risk.",
            How = "Renew with registrar; ensure RDAP metadata shows updated expiration.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdap", "expiry" },
            Impact = "Risk of domain lapse and outages.",
            Effort = RecommendationEffort.Low,
            Verify = "RDAP expiration event updated to a future date."
        };
        map[RdapCodes.ParseAnomaly] = new RecommendationAdvice {
            Code = RdapCodes.ParseAnomaly,
            Title = "RDAP parse anomaly",
            Why = "Missing or unexpected RDAP fields limit analysis.",
            How = "Inspect raw RDAP JSON and validate provider availability.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdap", "parsing" },
            Impact = "Limited visibility into domain lifecycle.",
            Effort = RecommendationEffort.Low,
            Verify = "RDAP JSON includes expected events and fields."
        };
        map[RdapCodes.RequestFailed] = new RecommendationAdvice {
            Code = RdapCodes.RequestFailed,
            Title = "RDAP request failed",
            Why = "HTTP error or provider limit prevented RDAP retrieval.",
            How = "Retry later; ensure firewall allows RDAP; use alternative server if available.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "rdap", "network" },
            Impact = "Uncertain registration status.",
            Effort = RecommendationEffort.Low,
            Verify = "RDAP request succeeds with status 200 and valid JSON."
        };
    }
}

