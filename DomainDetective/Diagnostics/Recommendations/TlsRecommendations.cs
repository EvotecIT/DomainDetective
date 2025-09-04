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

        map[TlsCodes.LegacyOffered] = new RecommendationAdvice {
            Code = TlsCodes.LegacyOffered,
            Title = "Server allows legacy TLS",
            Why = "Even when not negotiated, supporting TLS 1.0/1.1 increases attack surface and can be used in downgrade scenarios.",
            How = "Disable TLS 1.0 and 1.1. Restrict to TLS 1.2+ (preferably TLS 1.3).",
            Links = new [] { "https://datatracker.ietf.org/doc/rfc8996/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "legacy" },
            Impact = "Potential downgrade/compat risks; some clients may enforce TLS 1.2+.",
            Effort = RecommendationEffort.Low,
            Verify = "Attempt handshake restricted to TLS1.0/1.1 should fail."
        };

        map[TlsCodes.SctMissing] = new RecommendationAdvice {
            Code = TlsCodes.SctMissing,
            Title = "No embedded SCTs in certificate",
            Why = "Embedded Signed Certificate Timestamps (SCTs) provide immediate CT transparency without relying on Expect-CT.",
            How = "Obtain certificates from CAs that embed SCTs or use TLS extension SCT delivery.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6962" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ct", "sct" },
            Impact = "CT-monitoring relies on external validation; some clients prefer embedded SCTs.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect certificate extension 1.3.6.1.4.1.11129.2.4.2 to contain SCT list."
        };

        map[TlsCodes.OcspMustStapleMissing] = new RecommendationAdvice {
            Code = TlsCodes.OcspMustStapleMissing,
            Title = "No OCSP Must-Staple (TLS Feature)",
            Why = "OCSP Must-Staple requires stapled OCSP responses, strengthening revocation checking in clients that honor it.",
            How = "Consider enabling OCSP Must-Staple via the TLS Feature extension when operationally feasible.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc7633" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ocsp", "stapling" },
            Impact = "Clients may not strictly enforce revocation checks without stapling.",
            Effort = RecommendationEffort.Medium,
            Verify = "Certificate should include TLS Feature (status_request) extension."
        };

        map[TlsCodes.WeakCipherNegotiated] = new RecommendationAdvice {
            Code = TlsCodes.WeakCipherNegotiated,
            Title = "Weak cipher negotiated",
            Why = "Deprecated ciphers (e.g., 3DES/RC4) or CBC/SHA1-based suites reduce security and are deprecated.",
            How = "Disable weak/cbc/sha1 suites; prefer AEAD suites (TLS_AES_*, TLS_CHACHA20_POLY1305_*, TLS_ECDHE_* with GCM) and TLS 1.2/1.3.",
            Links = new [] { "https://datatracker.ietf.org/doc/rfc8996/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "cipher" },
            Impact = "Compromised confidentiality and integrity.",
            Effort = RecommendationEffort.Medium,
            Verify = "After changes, negotiated cipher suite should be modern and strong."
        };

        map[TlsCodes.WeakKeyExchange] = new RecommendationAdvice {
            Code = TlsCodes.WeakKeyExchange,
            Title = "Weak key exchange parameters",
            Why = "Diffie-Hellman parameters below 2048 bits are considered weak and vulnerable to attacks.",
            How = "Regenerate DH parameters with 2048+ bits or prefer ECDHE with modern curves.",
            Links = new [] { "https://weakdh.org/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "kex", "dh", "ecdhe" },
            Impact = "Forward secrecy protection is weakened; risk of compromise.",
            Effort = RecommendationEffort.Medium,
            Verify = "After changes, DH key size should be ≥ 2048 bits or ECDHE negotiated."
        };

        map[TlsCodes.OcspStaplingMissing] = new RecommendationAdvice {
            Code = TlsCodes.OcspStaplingMissing,
            Title = "OCSP stapling not detected",
            Why = "Without stapled OCSP responses, clients may fall back to slower or disabled revocation checks, reducing effective revocation coverage.",
            How = "Enable OCSP stapling on the server (web/mail). Ensure responders are reachable and configure cache/refresh intervals.",
            Links = new [] { "https://developer.mozilla.org/docs/Web/Security/OCSP_stapling" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ocsp", "stapling" },
            Impact = "Revocation status may be unavailable to clients or increase latency.",
            Effort = RecommendationEffort.Medium,
            Verify = "Probe with an OCSP-aware client (e.g., openssl s_client -status) to confirm response stapled."
        };

        // Positive signal (informational) – include to enrich datasets
        map[TlsCodes.OcspStaplingPresent] = new RecommendationAdvice {
            Code = TlsCodes.OcspStaplingPresent,
            Title = "OCSP stapling present",
            Why = "Stapled OCSP responses improve revocation checking performance and reliability for clients.",
            How = "Maintain stapling configuration and ensure responders remain reachable; monitor freshness of OCSP responses.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ocsp", "stapling" },
            Impact = "Better revocation coverage and lower client latency.",
            Effort = RecommendationEffort.Low,
            Verify = "Probe with an OCSP-aware client (openssl s_client -status) and confirm stapled response present."
        };
    }
}
