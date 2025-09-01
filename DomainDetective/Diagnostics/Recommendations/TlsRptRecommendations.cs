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

        map[TlsRptCodes.RuaHttpUnreachable] = new RecommendationAdvice {
            Code = TlsRptCodes.RuaHttpUnreachable,
            Title = "TLSRPT HTTPS report endpoint unreachable",
            Why = "Report processors cannot deliver failure reports to an endpoint that does not respond.",
            How = "Ensure the HTTPS endpoint is reachable and returns 2xx/3xx. Validate DNS, firewall rules, and TLS configuration.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting", "endpoint" }
        };

        map[TlsRptCodes.RuaHttpError] = new RecommendationAdvice {
            Code = TlsRptCodes.RuaHttpError,
            Title = "TLSRPT HTTPS report endpoint returns error",
            Why = "4xx/5xx responses prevent successful report delivery.",
            How = "Fix the endpoint to accept reports (2xx/3xx). Confirm authentication/format as required by your receiver.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting", "endpoint" }
        };
    }
}

