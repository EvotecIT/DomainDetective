using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class EdnsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[EdnsCodes.NotSupported] = new RecommendationAdvice {
            Code = EdnsCodes.NotSupported,
            Title = "Enable EDNS support on authoritative servers",
            Why = "EDNS allows larger DNS messages and is required by many modern features (DNSSEC, larger responses).",
            How = "Ensure your DNS software enables EDNS(0); upgrade or reconfigure servers and allow UDP payload ≥1232 bytes.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6891" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns" }
        };
    }
}

