using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class CertificateHttpRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[CertificateHttpCodes.FetchFailed] = new RecommendationAdvice {
            Code = CertificateHttpCodes.FetchFailed,
            Title = "Failed to retrieve TLS certificate",
            Why = "Could not read server certificate, preventing validation of HTTPS posture.",
            How = "Verify endpoint availability and TLS handshake. Check firewall, SNI, and protocol/cipher support.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "https", "certificate" },
            Impact = "TLS posture unknown; clients may fail to connect securely.",
            Effort = RecommendationEffort.Medium,
            Verify = "Connect with OpenSSL/curl; confirm certificate and chain are presented."
        };
        map[CertificateHttpCodes.ConnectFailed] = new RecommendationAdvice {
            Code = CertificateHttpCodes.ConnectFailed,
            Title = "HTTPS connection failed",
            Why = "Network or TLS negotiation failed; certificate and security headers could not be inspected.",
            How = "Ensure port 443 is reachable, ALPN configured correctly, and server supports TLS 1.2/1.3.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "https", "tls" },
            Impact = "Clients may be unable to establish secure connections.",
            Effort = RecommendationEffort.Low,
            Verify = "Retry with curl -v --tlsv1.2 and verify successful HTTP 200 over TLS."
        };
    }
}

