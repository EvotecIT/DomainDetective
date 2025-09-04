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
        map[OpenRelayCodes.Denied] = new RecommendationAdvice {
            Code = OpenRelayCodes.Denied,
            Title = "SMTP relay attempt denied",
            Why = "Server refused unauthenticated mail, preventing abuse.",
            How = "No action needed; maintain current restrictions.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "relay" },
            Impact = "Blocks unauthorized use of your mail server.",
            Effort = RecommendationEffort.Low,
            Verify = "Unauthenticated RCPT TO returns 550/551/554 or similar."
        };
        map[OpenRelayCodes.ConnectionFailed] = new RecommendationAdvice {
            Code = OpenRelayCodes.ConnectionFailed,
            Title = "SMTP relay connection failed",
            Why = "Server did not accept connection or relay, indicating no open relay.",
            How = "No action required.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "relay" },
            Impact = "Prevents unauthorized relaying from your infrastructure.",
            Effort = RecommendationEffort.Low,
            Verify = "Unauthenticated connection attempts are refused or time out."
        };
    }
}

