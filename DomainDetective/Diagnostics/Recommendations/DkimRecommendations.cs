using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DkimRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DkimCodes.KeyTooShort] = new RecommendationAdvice {
            Code = DkimCodes.KeyTooShort,
            Title = "DKIM public key is too short",
            Why = "Keys shorter than the platform minimum are vulnerable to brute-force attacks and are rejected by receivers.",
            How = "Generate a new DKIM selector and publish a TXT record with at least a 1024-bit key (2048-bit recommended). Rotate senders to use the new selector.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc6376", "https://dmarc.org/resources/specifications/" },
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "email", "dkim", "keys" }
        };
    }
}

