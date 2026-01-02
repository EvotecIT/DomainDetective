using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsPropagationRecommendations : IRecommendationProvider
{
    public void Register(IDictionary<string, RecommendationAdvice> map)
    {
        map[DnsPropagationCodes.NoServersSelected] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.NoServersSelected,
            Title = "Select resolvers for DNS propagation testing",
            Why = "Propagation checks require a list of public resolvers to compare answer sets across networks and regions.",
            How = "Provide a resolver list (built-in or custom) and rerun the propagation check for the desired record types.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "propagation" },
            Impact = "No visibility into global resolver differences.",
            Effort = RecommendationEffort.Low,
            Verify = "Propagation results show at least one successful resolver answer."
        };

        map[DnsPropagationCodes.QueryFailed] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.QueryFailed,
            Title = "Propagation queries failed on all resolvers",
            Why = "When all resolvers fail, the domain may be unresolvable, rate-limited, blocked, or experiencing connectivity issues.",
            How = "Verify the domain resolves from a known-good resolver, check authoritative DNS health, and retry with a different resolver set/timeouts.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "propagation", "resolution" },
            Impact = "Clients may fail to resolve the domain globally.",
            Effort = RecommendationEffort.Medium,
            Verify = "At least one resolver returns an answer set for the record type."
        };

        map[DnsPropagationCodes.ErrorsPresent] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.ErrorsPresent,
            Title = "Some propagation resolvers returned errors",
            Why = "Resolver failures can be caused by timeouts, rate limits, EDNS/transport differences, or regional blocking.",
            How = "Increase timeouts, retry later, and compare with authoritative answers to confirm whether issues are isolated or systemic.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "propagation", "timeouts" },
            Impact = "Partial loss of reachability in some regions/resolvers.",
            Effort = RecommendationEffort.Low,
            Verify = "Error count decreases and more resolvers return successful answers."
        };

        map[DnsPropagationCodes.InconsistentAnswers] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.InconsistentAnswers,
            Title = "Inconsistent DNS answers across resolvers",
            Why = "Inconsistency can indicate propagation delays, split-horizon configuration, resolver caching differences, or poisoning/manipulation.",
            How = "Compare against authoritative servers, ensure TTLs are reasonable, and confirm recent DNS changes have fully propagated.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "propagation", "drift" },
            Impact = "Users may reach different infrastructure depending on resolver.",
            Effort = RecommendationEffort.Medium,
            Verify = "All resolvers converge on a single answer set."
        };

        map[DnsPropagationCodes.NonPublicIpAddress] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.NonPublicIpAddress,
            Title = "Non-public IP returned by public resolvers",
            Why = "Private/loopback/link-local/ULA answers in public DNS can leak internal topology and enable DNS rebinding-style risks.",
            How = "Remove non-public answers from public DNS and ensure split-horizon DNS is configured intentionally and does not leak to public resolvers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "private-ip", "rebinding", "propagation" },
            Impact = "Potential access to internal resources and information disclosure.",
            Effort = RecommendationEffort.Medium,
            Verify = "Public resolvers return only publicly routable IP addresses."
        };

        map[DnsPropagationCodes.SplitHorizonSuspected] = new RecommendationAdvice
        {
            Code = DnsPropagationCodes.SplitHorizonSuspected,
            Title = "Possible split-horizon DNS detected",
            Why = "Mixed public and non-public answers across resolvers suggests split-horizon behavior or resolver-specific manipulation.",
            How = "Validate intended split-horizon configuration, confirm authoritative zone data, and ensure private views are not exposed publicly.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new[] { "dns", "split-horizon", "propagation" },
            Impact = "Users may resolve to internal-only endpoints or inconsistent destinations.",
            Effort = RecommendationEffort.Medium,
            Verify = "Resolver answers are consistent and publicly routable where intended."
        };
    }
}

