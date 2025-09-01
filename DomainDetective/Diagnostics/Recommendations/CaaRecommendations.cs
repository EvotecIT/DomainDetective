using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class CaaRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[CaaCodes.ReservedFlagBits] = new RecommendationAdvice {
            Code = CaaCodes.ReservedFlagBits,
            Title = "CAA flags use reserved bits",
            Why = "Non-standard flags may be ignored or cause issuance problems.",
            How = "Use only the critical bit (128) when required; otherwise 0.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "caa", "tls" },
            Impact = "CAs may refuse issuance.",
            Effort = RecommendationEffort.Low,
            Verify = "Check numeric flag field is 0 or 128."
        };

        map[CaaCodes.UnknownCriticalTag] = new RecommendationAdvice {
            Code = CaaCodes.UnknownCriticalTag,
            Title = "Unknown critical CAA tag",
            Why = "Critical unknown tags cause CAs to refuse issuance.",
            How = "Use known tags (issue, issuewild, iodef); avoid marking unknown tags as critical.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "caa", "tls" },
            Impact = "Certificate issuance blocked by CAs.",
            Effort = RecommendationEffort.Low,
            Verify = "Lint CAA tags; ensure critical applies only to supported tags."
        };

        map[CaaCodes.DuplicateIssuers] = new RecommendationAdvice {
            Code = CaaCodes.DuplicateIssuers,
            Title = "Duplicate CAA issuers",
            Why = "Redundant entries add confusion without additional control.",
            How = "Consolidate duplicate 'issue'/'issuewild' entries and keep a minimal set of authorized CAs.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "caa" },
            Impact = "Harder policy management and potential misinterpretations.",
            Effort = RecommendationEffort.Low,
            Verify = "List unique issuers; remove duplicates."
        };
    }
}
