using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ArcRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ArcCodes.ParseFailed] = new RecommendationAdvice {
            Code = ArcCodes.ParseFailed,
            Title = "ARC header parsing failed",
            Why = "Malformed ARC headers prevent validation of the forwarding chain (RFC 8617).",
            How = "Ensure each ARC instance has one Seal, Message-Signature, and Authentication-Results header with the required fields.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc", "headers" },
            Impact = "Authentication results may not survive forwarding.",
            Effort = RecommendationEffort.Low,
            Verify = "Re-parse headers and confirm a valid sequential ARC chain."
        };

        map[ArcCodes.ChainValid] = new RecommendationAdvice {
            Code = ArcCodes.ChainValid,
            Title = "ARC header structure complete",
            Why = "Every instance has the required headers in a sequential structure. This check does not verify their cryptographic signatures.",
            How = "Verify the original MIME message and assess sealer trust before relying on forwarded authentication claims.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc" },
            Impact = "The headers provide a complete structure for subsequent cryptographic verification.",
            Effort = RecommendationEffort.Low,
            Verify = "Use ARC validation tools to confirm chain integrity."
        };

        map[ArcCodes.SealsIntact] = new RecommendationAdvice {
            Code = ArcCodes.SealsIntact,
            Title = "ARC seals contain signature values",
            Why = "The Seal headers contain non-empty b= values; their presence alone does not establish signature validity.",
            How = "Maintain ARC signing so every hop seals messages with a valid signature.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "arc", "seal" },
            Impact = "Signature values are available for cryptographic verification.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect ARC-Seal headers for non-empty b= signatures."
        };
    }
}

