using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DaneRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DaneCodes.NoRecords] = new RecommendationAdvice {
            Code = DaneCodes.NoRecords,
            Title = "No DANE TLSA records found",
            Why = "Without DANE, SMTP/HTTPS clients cannot pin certificates via DNSSEC.",
            How = "Publish TLSA records at _<port>._<proto>.<host> with correct usage/selector/matching values.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa", "dnssec" },
            Impact = "Reduced resilience against MITM for TLS connections.",
            Effort = RecommendationEffort.Medium,
            Verify = "dig _25._tcp.mail.example.com TLSA and validate fields."
        };
        map[DaneCodes.UsageNotNumeric] = new RecommendationAdvice {
            Code = DaneCodes.UsageNotNumeric,
            Title = "TLSA usage not numeric",
            Why = "Non-numeric usage prevents clients from interpreting TLSA records.",
            How = "Use 0..3 per RFC 6698/7671 depending on pinning strategy.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.UsageInvalid] = new RecommendationAdvice {
            Code = DaneCodes.UsageInvalid,
            Title = "Invalid TLSA usage value",
            Why = "Unsupported usage value breaks DANE validation.",
            How = "Choose one of PKIX-TA(0), PKIX-EE(1), DANE-TA(2), DANE-EE(3).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.SelectorNotNumeric] = new RecommendationAdvice {
            Code = DaneCodes.SelectorNotNumeric,
            Title = "TLSA selector not numeric",
            Why = "Non-numeric selector breaks client parsing.",
            How = "Use 0 (Cert) or 1 (SPKI).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.SelectorInvalid] = new RecommendationAdvice {
            Code = DaneCodes.SelectorInvalid,
            Title = "Invalid TLSA selector value",
            Why = "Unsupported selector value breaks DANE.",
            How = "Use 0 (full cert) or 1 (SPKI).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.MatchingTypeNotNumeric] = new RecommendationAdvice {
            Code = DaneCodes.MatchingTypeNotNumeric,
            Title = "TLSA matching type not numeric",
            Why = "Non-numeric matching type breaks DANE.",
            How = "Use 0 (full), 1 (SHA-256) or 2 (SHA-512).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.MatchingTypeInvalid] = new RecommendationAdvice {
            Code = DaneCodes.MatchingTypeInvalid,
            Title = "Invalid TLSA matching type",
            Why = "Unsupported matching type breaks DANE.",
            How = "Use 0, 1 or 2 per spec.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" }
        };
        map[DaneCodes.ComboNotRecommended] = new RecommendationAdvice {
            Code = DaneCodes.ComboNotRecommended,
            Title = "Non-recommended TLSA selector/matching combination",
            Why = "Certain combinations are discouraged for SMTP/HTTPS interoperability.",
            How = "Prefer SPKI (1) with SHA-256 (1) or SHA-512 (2) for pinning.",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "tlsa" },
            Verify = "Confirm clients can validate using the published TLSA."
        };

        map[DaneCodes.AlignmentMissingForMx] = new RecommendationAdvice {
            Code = DaneCodes.AlignmentMissingForMx,
            Title = "No TLSA coverage for MX hosts",
            Why = "When using DANE for SMTP, TLSA should exist for each MX endpoint to enable pinning.",
            How = "Publish TLSA at _25._tcp.<mx-host> for all MX targets (or at the parent when appropriate).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "smtp", "mx" },
            Impact = "MTAs cannot validate pinned keys, reducing protection against MITM.",
            Effort = RecommendationEffort.Medium,
            Verify = "dig _25._tcp.<mx-host> TLSA returns records for all MX hosts."
        };

        map[DaneCodes.AlignmentTlsWeak] = new RecommendationAdvice {
            Code = DaneCodes.AlignmentTlsWeak,
            Title = "TLSA present but negotiated TLS is weak",
            Why = "Legacy protocols or invalid certificates undermine the value of DANE pinning.",
            How = "Disable TLS1.0/1.1; ensure valid chains/hostnames; prefer TLS1.2+ (ideally TLS1.3).",
            Domain = RecommendationDomain.Tls,
            Tags = new [] { "dane", "smtp", "tls" },
            Impact = "Receivers may reject connections; pinning provides limited assurance.",
            Effort = RecommendationEffort.Medium,
            Verify = "Re-test STARTTLS; handshake negotiates TLS1.2+ with valid hostname and chain."
        };
    }
}

