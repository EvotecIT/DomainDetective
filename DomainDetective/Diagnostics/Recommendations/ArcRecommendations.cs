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

        map[ArcCodes.ChainValid] = new RecommendationAdvice {
            Code = ArcCodes.ChainValid,
            Title = "ARC chain validated",
            Why = "A complete, sequential ARC chain preserves authentication results across forwarding hops.",
            How = "No action needed. Continue signing and validating ARC headers for forwarded mail.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc" },
            Impact = "Receivers can trust the original authentication context.",
            Effort = RecommendationEffort.Low,
            Verify = "Use ARC validation tools to confirm chain integrity."
        };

        map[ArcCodes.SealsIntact] = new RecommendationAdvice {
            Code = ArcCodes.SealsIntact,
            Title = "ARC seals include signatures",
            Why = "Signed ARC-Seal headers ensure each intermediary's contribution is tamper-evident.",
            How = "Maintain ARC signing so every hop seals messages with a valid signature.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc", "seal" },
            Impact = "Improves trust in messages handled by intermediaries.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect ARC-Seal headers for non-empty b= signatures."
        };
    }
}

