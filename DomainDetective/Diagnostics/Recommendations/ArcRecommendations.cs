using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ArcRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ArcCodes.ParseFailed] = new RecommendationAdvice {
            Code = ArcCodes.ParseFailed,
            Title = "ARC header parsing failed",
            Why = "Malformed ARC headers prevent validation of the forwarding chain (RFC 8617).",
            How = "Ensure ARC-Seal and ARC-Authentication-Results headers are syntactically correct and include 'i=' and 'b=' parameters.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc", "headers" },
            Impact = "Authentication results may not survive forwarding.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-parse headers and confirm a valid sequential ARC chain."
        };
    }
}

