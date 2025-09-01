using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class OpenRelayRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[OpenRelayCodes.AllowsRelay] = new RecommendationAdvice {
            Code = OpenRelayCodes.AllowsRelay,
            Title = "SMTP server allows unauthenticated relay",
            Why = "Open relays enable spam and abuse from your infrastructure and will quickly damage domain/IP reputation.",
            How = "Disable relaying from unauthenticated/unauthorized clients. Require SMTP AUTH and restrict relay to trusted networks only.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "relay", "abuse" },
            Impact = "High risk of blacklisting and outbound abuse.",
            Effort = RecommendationEffort.Medium,
            Verify = "Attempt unauthenticated RCPT TO for external recipient returns 550/551/554 and no delivery occurs."
        };
        map[OpenRelayCodes.CheckFailed] = new RecommendationAdvice {
            Code = OpenRelayCodes.CheckFailed,
            Title = "Open relay check failed",
            Why = "Network or server errors prevented validation, hiding potential exposure.",
            How = "Retry from a stable network, verify SMTP port reachability, and confirm server banner.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "relay" },
            Impact = "Uncertain relay posture.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-run the relay test; expect explicit denial codes for unauthenticated relay attempts."
        };
    }
}

