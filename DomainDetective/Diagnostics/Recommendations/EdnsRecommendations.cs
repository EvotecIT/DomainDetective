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

        map[EdnsCodes.BufferTooLarge] = new RecommendationAdvice {
            Code = EdnsCodes.BufferTooLarge,
            Title = "EDNS UDP buffer too large (risk of fragmentation)",
            Why = "Advertising >1232 bytes over UDP can cause fragmentation and packet loss on common path MTUs.",
            How = "Configure EDNS UDP payload to 1232 or lower unless you control path MTU; enable TCP fallback.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8900" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "mtu" }
        };

        map[EdnsCodes.TruncatedFallback] = new RecommendationAdvice {
            Code = EdnsCodes.TruncatedFallback,
            Title = "EDNS responses truncated; TCP fallback used",
            Why = "Large DNS responses may require TCP fallback; ensure TCP/53 isn’t blocked by firewalls.",
            How = "Permit TCP/53 to authoritative servers and ensure DNS software handles truncation correctly.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7766" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "tcp" }
        };
    }
}
