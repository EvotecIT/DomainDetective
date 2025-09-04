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

        // Positive signals (informational)
        map[CertificateHttpCodes.ChainValid] = new RecommendationAdvice {
            Code = CertificateHttpCodes.ChainValid,
            Title = "Certificate chain valid",
            Why = "A complete, trusted certificate chain allows clients to verify server identity.",
            How = "Continue monitoring certificate expiration and intermediate CA trust.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "certificate" },
            Impact = "Users see no trust warnings when connecting over HTTPS.",
            Effort = RecommendationEffort.Low,
            Verify = "Run openssl s_client -showcerts and confirm the chain verifies without errors."
        };
        map[CertificateHttpCodes.ContentTypeValid] = new RecommendationAdvice {
            Code = CertificateHttpCodes.ContentTypeValid,
            Title = "Serves certificate with correct content type",
            Why = "Proper Content-Type headers ensure automated tools parse certificate responses reliably.",
            How = "Keep the endpoint configured to return application/pem-certificate-chain or application/x-pem-file.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "https", "content-type" },
            Impact = "Clients can download certificates programmatically without additional handling.",
            Effort = RecommendationEffort.Low,
            Verify = "Fetch the certificate URL and inspect the Content-Type header."
        };
    }
}

