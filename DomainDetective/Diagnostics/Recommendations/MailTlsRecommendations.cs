using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MailTlsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MailTlsCodes.TlsCheckFailed] = new RecommendationAdvice {
            Code = MailTlsCodes.TlsCheckFailed,
            Title = "SMTP TLS check failed",
            Why = "TLS handshake, certificate, or protocol issues degrade mail security and deliverability.",
            How = "Use valid certificates (SAN covers MX), enable TLS 1.2+ and modern ciphers, and ensure chain completeness.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc7817", "https://ssl-config.mozilla.org/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "smtp", "tls" }
        };
    }
}

