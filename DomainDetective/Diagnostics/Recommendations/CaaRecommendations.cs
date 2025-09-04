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

        map[CaaCodes.RecordPresent] = new RecommendationAdvice {
            Code = CaaCodes.RecordPresent,
            Title = "CAA record present",
            Why = "Restricts certificate issuance to specified authorities.",
            How = "Maintain the authorized CA list to match organizational requirements.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "caa", "tls" },
            Impact = "Reduces risk of unauthorized certificates.",
            Effort = RecommendationEffort.Low,
            Verify = "Query CAA records and confirm expected issuers."
        };

        map[CaaCodes.IodefPresent] = new RecommendationAdvice {
            Code = CaaCodes.IodefPresent,
            Title = "CAA reporting endpoint present",
            Why = "Enables CAs to report unauthorized certificate requests.",
            How = "Monitor the listed contact address or URL for CAA violation reports.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8659" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "caa", "reporting" },
            Impact = "Provides visibility into certificate issuance attempts.",
            Effort = RecommendationEffort.Low,
            Verify = "CAA record includes an iodef tag with a reachable URI."
        };
    }
}
