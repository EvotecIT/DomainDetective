using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ReverseDnsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ReverseDnsCodes.TruncatedNoRecords] = new RecommendationAdvice {
            Code = ReverseDnsCodes.TruncatedNoRecords,
            Title = "Reverse DNS not found or truncated",
            Why = "Missing or truncated PTR records hinder diagnostics and may affect reputation checks.",
            How = "Ensure authoritative PTR exists for IPs and responses fit in UDP or allow TCP fallback.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr" }
        };

        map[ReverseDnsCodes.MalformedPtr] = new RecommendationAdvice {
            Code = ReverseDnsCodes.MalformedPtr,
            Title = "Malformed PTR record",
            Why = "Badly formatted PTR names can break reverse lookups and validation.",
            How = "Publish PTR names as valid FQDNs ending with a dot; avoid invalid characters.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr" }
        };
    }
}

