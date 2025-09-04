using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class CnameRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TakeoverCnameCodes.RiskyProvider] = new RecommendationAdvice {
            Code = TakeoverCnameCodes.RiskyProvider,
            Title = "CNAME target on takeover-prone provider",
            Why = "Unclaimed targets can be registered by attackers to hijack the subdomain.",
            How = "Verify the target resource is claimed. If unused, remove the CNAME. Consider provider-specific hardening guidance.",
            Links = new [] { "https://github.com/EdOverflow/can-i-take-over-xyz" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "takeover", "cname" },
            Impact = "Subdomain takeover can lead to phishing and data loss.",
            Effort = RecommendationEffort.Medium,
            Verify = "Check target resource exists/owned; attempt to claim if missing (in non-prod)."
        };

        map[DanglingCnameCodes.TargetDoesNotResolve] = new RecommendationAdvice {
            Code = DanglingCnameCodes.TargetDoesNotResolve,
            Title = "Dangling CNAME target",
            Why = "Targets that do not resolve may be claimable by attackers (subdomain takeover risk).",
            How = "Either remove the CNAME or recreate/claim the target at the provider.",
            Links = new [] { "https://owasp.org/www-community/attacks/Subdomain_takeover" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "takeover", "cname" },
            Impact = "Risk of domain impersonation and data exfiltration.",
            Effort = RecommendationEffort.Low,
            Verify = "Resolve target; if NXDOMAIN, confirm service state and owner."
        };

        map[CnameCodes.TargetResolves] = new RecommendationAdvice {
            Code = CnameCodes.TargetResolves,
            Title = "CNAME target resolves",
            Why = "A resolving target confirms the alias points to an active destination, avoiding dangling records.",
            How = "Keep the target record in service and monitor for changes.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "cname" },
            Impact = "Improves reliability and reduces takeover risk.",
            Effort = RecommendationEffort.Low,
            Verify = "Resolve the CNAME target and confirm A/AAAA records exist."
        };

        map[CnameCodes.NoLoop] = new RecommendationAdvice {
            Code = CnameCodes.NoLoop,
            Title = "No CNAME loop detected",
            Why = "A well-formed CNAME chain terminates cleanly without redirecting back to itself.",
            How = "No change required; retain current alias structure.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "cname" },
            Impact = "Prevents resolver failures caused by misconfiguration.",
            Effort = RecommendationEffort.Low,
            Verify = "Follow the CNAME chain and confirm it reaches a final target."
        };
    }
}
