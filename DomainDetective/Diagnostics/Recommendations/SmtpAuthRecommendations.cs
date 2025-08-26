using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SmtpAuthRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SmtpAuthCodes.AuthWithout8BitMime] = new RecommendationAdvice {
            Code = SmtpAuthCodes.AuthWithout8BitMime,
            Title = "AUTH advertised without 8BITMIME",
            Why = "Some clients expect 8BITMIME when AUTH is present; missing it can cause encoding issues.",
            How = "Enable the 8BITMIME extension alongside AUTH in EHLO capabilities.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6152" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "auth" },
            Impact = "Intermittent client failures with non-ASCII content.",
            Effort = RecommendationEffort.Low,
            Verify = "Check EHLO response lists 8BITMIME and AUTH."
        };

        map[SmtpAuthCodes.CheckFailed] = new RecommendationAdvice {
            Code = SmtpAuthCodes.CheckFailed,
            Title = "SMTP AUTH check failed",
            Why = "Authentication capability is misconfigured or failing; clients may fall back to insecure methods.",
            How = "Verify SASL mechanisms, TLS protection, and server logs for AUTH negotiation errors.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc4954" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "smtp", "auth" }
        };
    }
}
