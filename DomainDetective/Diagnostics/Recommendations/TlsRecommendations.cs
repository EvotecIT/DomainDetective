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
            Why = "Chrome and Apple platforms reject publicly trusted certificates without enough SCTs. SCTs delivered through the TLS extension or OCSP stapling were not observed by this check.",
            How = "Obtain certificates from a CA that embeds SCTs, or confirm that the server delivers SCTs through the TLS extension.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6962", "https://googlechrome.github.io/CertificateTransparency/ct_policy.html", "https://support.apple.com/en-us/103214" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ct", "sct" },
            Impact = "Expected for private CAs; a publicly trusted certificate without SCTs fails in Chrome and Safari unless SCTs arrive another way.",
            Effort = RecommendationEffort.Low,
            Verify = "Inspect certificate extension 1.3.6.1.4.1.11129.2.4.2 to contain SCT list."
        };

        map[TlsCodes.SctInvalid] = new RecommendationAdvice {
            Code = TlsCodes.SctInvalid,
            Title = "Embedded SCTs are malformed or do not verify",
            Why = "Browsers ignore SCTs whose list cannot be parsed or whose signature does not verify against the CT log key.",
            How = "Reissue the certificate from the CA and report the faulty SCTs to it.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6962#section-3.2" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ct", "sct" },
            Impact = "Invalid SCTs do not count toward browser CT policies and can cause connection failures.",
            Effort = RecommendationEffort.Low,
            Verify = "Every embedded SCT signature verifies against its log key."
        };

        map[TlsCodes.CtPolicyNotCompliant] = new RecommendationAdvice {
            Code = TlsCodes.CtPolicyNotCompliant,
            Title = "Embedded SCTs do not meet a browser CT policy",
            Why = "Chrome and Apple require SCTs from enough distinct, approved CT logs and operators for the certificate lifetime.",
            How = "Reissue the certificate from a CA that embeds SCTs meeting current policy, or deliver compliant SCTs through the TLS extension.",
            Links = new [] { "https://googlechrome.github.io/CertificateTransparency/ct_policy.html", "https://support.apple.com/en-us/103214" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "ct", "sct" },
            Impact = "Unless SCTs arrive through the TLS extension, the affected browser rejects the certificate.",
            Effort = RecommendationEffort.Medium,
            Verify = "Embedded SCT policy results report Compliant for Chrome and Apple."
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

        map[TlsCodes.StrongProtocol] = new RecommendationAdvice {
            Code = TlsCodes.StrongProtocol,
            Title = "Modern TLS protocol negotiated",
            Why = "Using TLS 1.2 or 1.3 provides strong encryption and broad client compatibility.",
            How = "Keep TLS 1.2/1.3 enabled and disable older protocols when possible.",
            Links = new [] { "https://datatracker.ietf.org/doc/rfc8996/" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "protocol" },
            Impact = "Reduces exposure to known protocol attacks and meets industry requirements.",
            Effort = RecommendationEffort.Low,
            Verify = "Handshake should negotiate TLS 1.2 or TLS 1.3."
        };

        map[TlsCodes.PfsCipher] = new RecommendationAdvice {
            Code = TlsCodes.PfsCipher,
            Title = "Forward secrecy cipher suite negotiated",
            Why = "Perfect forward secrecy prevents compromise of past sessions if keys are exposed.",
            How = "Prefer ECDHE/DHE-based cipher suites such as TLS_AES_* or TLS_CHACHA20_POLY1305_*.",
            Links = new [] { "https://en.wikipedia.org/wiki/Perfect_forward_secrecy" },
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "tls", "pfs", "cipher" },
            Impact = "Protects historical traffic even if long-term keys are compromised.",
            Effort = RecommendationEffort.Low,
            Verify = "Confirm handshake negotiates an ECDHE or DHE cipher suite."
        };
    }
}
