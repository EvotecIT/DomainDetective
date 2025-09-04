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

        map[TlsRptCodes.RecordPresent] = new RecommendationAdvice {
            Code = TlsRptCodes.RecordPresent,
            Title = "TLSRPT record present",
            Why = "A TLSRPT record provides destinations for TLS failure reports.",
            How = "Monitor the listed addresses to detect TLS delivery issues early.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting" }
        };

        map[TlsRptCodes.RecordStartsV1] = new RecommendationAdvice {
            Code = TlsRptCodes.RecordStartsV1,
            Title = "TLSRPT starts with v=TLSRPTv1",
            Why = "The correct version tag ensures receivers recognize the policy.",
            How = "No action needed.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting" }
        };

        map[TlsRptCodes.RuaMailtoPresent] = new RecommendationAdvice {
            Code = TlsRptCodes.RuaMailtoPresent,
            Title = "TLSRPT mailto RUA configured",
            Why = "Mailto destinations receive aggregated TLS failure reports.",
            How = "Review reports to remediate delivery issues.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting" }
        };

        map[TlsRptCodes.RuaHttpPresent] = new RecommendationAdvice {
            Code = TlsRptCodes.RuaHttpPresent,
            Title = "TLSRPT HTTPS RUA configured",
            Why = "HTTPS endpoints can accept JSON reports securely.",
            How = "Ensure the endpoint is maintained and monitored.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting", "endpoint" }
        };

        map[TlsRptCodes.PolicyValid] = new RecommendationAdvice {
            Code = TlsRptCodes.PolicyValid,
            Title = "TLSRPT policy valid",
            Why = "A valid policy enables reliable reporting of TLS issues.",
            How = "No action required.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8460" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tlsrpt", "reporting" }
        };
    }
}

