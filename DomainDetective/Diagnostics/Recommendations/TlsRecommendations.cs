using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class TlsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TlsCodes.LegacyEnabled] = new RecommendationAdvice {
            Code = TlsCodes.LegacyEnabled,
            Title = "Legacy TLS protocol negotiated",
            Why = "TLS 1.0/1.1 (or SSLv3) are deprecated and considered insecure by modern clients.",
            How = "Disable TLS 1.0/1.1 and SSLv3 on servers; require TLS 1.2+ (ideally TLS 1.3).",
            Links = new [] { "https://datatracker.ietf.org/doc/rfc8996/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "smtp", "imap", "pop3" },
            Impact = "Legacy protocols weaken confidentiality and may be blocked by receivers.",
            Effort = RecommendationEffort.Medium,
            Verify = "After changes, handshake negotiates TLS 1.2 or TLS 1.3 only."
        };
    }
}

