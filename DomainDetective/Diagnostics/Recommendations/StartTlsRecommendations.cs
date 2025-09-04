using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class StartTlsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[StartTlsCodes.BannerUnexpected] = new RecommendationAdvice {
            Code = StartTlsCodes.BannerUnexpected,
            Title = "Unexpected SMTP banner sequence",
            Why = "Non-RFC compliant banners can break SMTP clients and automated checks.",
            How = "Ensure server greets with a single 220 banner and follows RFC 5321 semantics.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "starttls" }
        };

        map[StartTlsCodes.EhloUnexpected] = new RecommendationAdvice {
            Code = StartTlsCodes.EhloUnexpected,
            Title = "Unexpected EHLO response",
            Why = "Malformed EHLO lines confuse capability negotiation including STARTTLS.",
            How = "Return 250-lines with valid keywords; terminate with final 250 per RFC 5321.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "starttls" },
            Impact = "Clients may not advertise or attempt STARTTLS.",
            Effort = RecommendationEffort.Low,
            Verify = "Connect via telnet and check EHLO multi-line 250 responses."
        };

        map[StartTlsCodes.EhloMissingFinal250] = new RecommendationAdvice {
            Code = StartTlsCodes.EhloMissingFinal250,
            Title = "EHLO response missing final 250",
            Why = "Clients may misparse capability list without the final 250 line.",
            How = "Terminate multi-line EHLO capabilities with a final 250 response.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "starttls" }
        };

        map[StartTlsCodes.CheckFailed] = new RecommendationAdvice {
            Code = StartTlsCodes.CheckFailed,
            Title = "STARTTLS check failed",
            Why = "TLS negotiation or state machine failed; mail security and delivery may be impacted.",
            How = "Verify TLS certificates, ciphers, and server compliance with STARTTLS negotiation.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc7817" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "starttls" }
        };

        map[StartTlsCodes.Enforced] = new RecommendationAdvice {
            Code = StartTlsCodes.Enforced,
            Title = "STARTTLS enforced",
            Why = "Servers requiring TLS upgrades prevent plaintext fallback.",
            How = "Monitor for downgrade attempts and maintain strong TLS settings.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc3207" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "imap", "pop", "starttls" }
        };

        map[StartTlsCodes.ModernCipher] = new RecommendationAdvice {
            Code = StartTlsCodes.ModernCipher,
            Title = "Modern cipher suite negotiated",
            Why = "Modern TLS ciphers protect against known weaknesses.",
            How = "Keep TLS libraries and configuration up to date to retain strong cipher support.",
            Links = new [] { "https://ssl-config.mozilla.org/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "starttls", "tls" }
        };
    }
}
