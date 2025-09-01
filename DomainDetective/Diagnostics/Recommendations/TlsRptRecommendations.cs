using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class TlsRptRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TlsRptCodes.MissingRua] = new RecommendationAdvice {
            Code = TlsRptCodes.MissingRua,
            Title = "TLSRPT missing 'rua' report URI",
            Why = "Without a reporting address, you won't receive TLS failure reports for your domain.",
            How = "Publish a TLSRPT TXT at _smtp._tls.<domain> with 'v=TLSRPTv1; rua=mailto:reports@<domain>'.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting" }
        };
    }
}

