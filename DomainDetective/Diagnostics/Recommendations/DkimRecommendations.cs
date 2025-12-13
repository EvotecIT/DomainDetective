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
        map[DkimCodes.SignatureValid] = new RecommendationAdvice {
            Code = DkimCodes.SignatureValid,
            Title = "DKIM signature validated",
            Why = "A valid DKIM signature helps receivers verify message authenticity.",
            How = "Keep rotating keys regularly and monitor for verification failures.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "email", "authentication" }
        };
        map[DkimCodes.SelectorAligned] = new RecommendationAdvice {
            Code = DkimCodes.SelectorAligned,
            Title = "DKIM selectors aligned",
            Why = "Aligned selectors simplify management and reduce deliverability issues.",
            How = "Maintain consistent selector naming across all sending services.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "selectors" }
        };
        map[DkimCodes.AlgorithmRecommended] = new RecommendationAdvice {
            Code = DkimCodes.AlgorithmRecommended,
            Title = "Recommended DKIM algorithm in use",
            Why = "Modern algorithms like rsa-sha256 or ed25519-sha256 provide strong signatures.",
            How = "Continue using modern algorithms and phase out weaker ones.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "crypto", "algorithm" }
        };

        map[DkimCodes.KeyReused] = new RecommendationAdvice {
            Code = DkimCodes.KeyReused,
            Title = "DKIM key reused across selectors",
            Why = "Reusing the same DKIM key across selectors/services reduces isolation and complicates key rotation.",
            How = "Issue unique keys per selector/service and rotate regularly; decommission old keys.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc6376" },
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "keys", "rotation" }
        };

        map[DkimCodes.SelectorsMinimumMet] = new RecommendationAdvice {
            Code = DkimCodes.SelectorsMinimumMet,
            Title = "Recommended number of DKIM selectors present",
            Why = "Having multiple selectors simplifies rotation and continuity.",
            How = "Continue to maintain at least the recommended number of selectors for the detected provider.",
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "selectors" }
        };
        map[DkimCodes.SelectorsMinimumNotMet] = new RecommendationAdvice {
            Code = DkimCodes.SelectorsMinimumNotMet,
            Title = "Add additional DKIM selector(s)",
            Why = "The detected provider recommends multiple selectors for safe rotation and resilience.",
            How = "Publish at least the minimum number of selectors (e.g., selector1/selector2 for Microsoft 365) and configure signing.",
            Domain = RecommendationDomain.Dkim,
            Tags = new [] { "dkim", "selectors" }
        };
    }
}

