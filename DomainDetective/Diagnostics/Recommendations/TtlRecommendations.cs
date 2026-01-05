using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class TtlRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[TtlCodes.TooShortForDnssec] = new RecommendationAdvice {
            Code = TtlCodes.TooShortForDnssec,
            Title = "Increase TTL for DNSSEC-signed zones",
            Why = "Very low TTLs increase validation load and can cause frequent cache misses in signed zones.",
            How = "Prefer TTLs ≥ 3600 seconds for A/AAAA/MX/NS/SOA when DNSSEC is enabled; adjust to your change cadence.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "dnssec", "ttl" }
        };

        map[TtlCodes.TooShort] = new RecommendationAdvice {
            Code = TtlCodes.TooShort,
            Title = "Raise DNS TTL to reduce churn",
            Why = "Very short TTLs increase resolver traffic and can degrade performance.",
            How = "Use TTLs ≥ 300 seconds for steady-state; lower temporarily during planned changes only.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.TooLong] = new RecommendationAdvice {
            Code = TtlCodes.TooLong,
            Title = "Lower excessive DNS TTLs",
            Why = "Excessive TTLs delay propagation of necessary changes and incident response.",
            How = "Target TTLs ≤ 86400 seconds for typical records; shorten when frequent changes are expected.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.A_AAAA_Mismatch] = new RecommendationAdvice {
            Code = TtlCodes.A_AAAA_Mismatch,
            Title = "Align A and AAAA TTLs",
            Why = "Large TTL differences between A and AAAA can cause inconsistent client behavior.",
            How = "Set similar TTLs for A and AAAA records to ensure consistent caching.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.Optimal] = new RecommendationAdvice {
            Code = TtlCodes.Optimal,
            Title = "DNS TTLs within recommended range",
            Why = "Balanced TTLs reduce lookup load while still allowing timely updates.",
            How = "Maintain TTLs between 300 and 86400 seconds; use ≥3600s when DNSSEC is enabled.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.A_AAAA_Aligned] = new RecommendationAdvice {
            Code = TtlCodes.A_AAAA_Aligned,
            Title = "A and AAAA TTLs aligned",
            Why = "Consistent IPv4 and IPv6 TTLs ensure uniform caching behavior across clients.",
            How = "Keep A and AAAA records synchronized with matching TTL values.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        map[TtlCodes.UniformAcrossNS_A] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_A,
            Title = "A TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Ensure zone transfers propagate TTL updates to all authoritative servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };
        map[TtlCodes.UniformAcrossNS_AAAA] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_AAAA,
            Title = "AAAA TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Ensure zone transfers propagate TTL updates to all authoritative servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };
        map[TtlCodes.UniformAcrossNS_NS] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_NS,
            Title = "NS TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Ensure zone transfers propagate TTL updates to all authoritative servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };
        map[TtlCodes.UniformAcrossNS_CNAME] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_CNAME,
            Title = "CNAME TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Ensure zone transfers propagate TTL updates to all authoritative servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl" }
        };

        // TXT categories
        map[TtlCodes.NonUniformAcrossNS_TXT_SPF] = new RecommendationAdvice {
            Code = TtlCodes.NonUniformAcrossNS_TXT_SPF,
            Title = "SPF TXT TTL differs across name servers",
            Why = "Inconsistent TTLs across authoritative servers lead to unpredictable caching.",
            How = "Publish consistent TTLs for apex TXT (SPF) across all authoritative name servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl", "spf" }
        };
        map[TtlCodes.UniformAcrossNS_TXT_SPF] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_TXT_SPF,
            Title = "SPF TXT TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Keep TTLs aligned; target ≥3600s for policy records.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl", "spf" }
        };
	        map[TtlCodes.NonUniformAcrossNS_TXT_DMARC] = new RecommendationAdvice {
	            Code = TtlCodes.NonUniformAcrossNS_TXT_DMARC,
	            Title = "DMARC TXT TTL differs across name servers",
	            Why = "Inconsistent TTLs across authoritative servers lead to unpredictable caching.",
	            How = "Publish consistent TTLs for _dmarc TXT across all authoritative name servers.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "dmarc" }
	        };
	        map[TtlCodes.UniformAcrossNS_TXT_DMARC] = new RecommendationAdvice {
	            Code = TtlCodes.UniformAcrossNS_TXT_DMARC,
	            Title = "DMARC TXT TTL uniform across name servers",
	            Why = "Consistent TTLs simplify caching and diagnostics.",
	            How = "Keep TTLs aligned; target ≥3600s for policy records.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "dmarc" }
	        };
	        map[TtlCodes.NonUniformAcrossNS_TXT_MTASTS] = new RecommendationAdvice {
	            Code = TtlCodes.NonUniformAcrossNS_TXT_MTASTS,
	            Title = "MTA-STS TXT TTL differs across name servers",
	            Why = "Inconsistent TTLs across authoritative servers lead to unpredictable caching.",
	            How = "Publish consistent TTLs for _mta-sts TXT across all authoritative name servers.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "mta-sts" }
	        };
	        map[TtlCodes.UniformAcrossNS_TXT_MTASTS] = new RecommendationAdvice {
	            Code = TtlCodes.UniformAcrossNS_TXT_MTASTS,
	            Title = "MTA-STS TXT TTL uniform across name servers",
	            Why = "Consistent TTLs simplify caching and diagnostics.",
	            How = "Keep TTLs aligned; target ≥3600s for policy records.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "mta-sts" }
	        };
	        map[TtlCodes.NonUniformAcrossNS_TXT_TLSRPT] = new RecommendationAdvice {
	            Code = TtlCodes.NonUniformAcrossNS_TXT_TLSRPT,
	            Title = "TLS-RPT TXT TTL differs across name servers",
	            Why = "Inconsistent TTLs across authoritative servers lead to unpredictable caching.",
	            How = "Publish consistent TTLs for _smtp._tls TXT across all authoritative name servers.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "tls-rpt" }
	        };
	        map[TtlCodes.UniformAcrossNS_TXT_TLSRPT] = new RecommendationAdvice {
	            Code = TtlCodes.UniformAcrossNS_TXT_TLSRPT,
	            Title = "TLS-RPT TXT TTL uniform across name servers",
	            Why = "Consistent TTLs simplify caching and diagnostics.",
	            How = "Keep TTLs aligned; target ≥3600s for policy records.",
	            Domain = RecommendationDomain.Infrastructure,
	            Tags = new [] { "dns", "ttl", "tls-rpt" }
	        };
	        map[TtlCodes.NonUniformAcrossNS_TXT_DKIM] = new RecommendationAdvice {
	            Code = TtlCodes.NonUniformAcrossNS_TXT_DKIM,
	            Title = "DKIM TXT TTL differs across name servers",
	            Why = "Inconsistent TTLs across authoritative servers lead to unpredictable caching.",
            How = "Publish consistent TTLs for selector TXT records across all authoritative name servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl", "dkim" }
        };
        map[TtlCodes.UniformAcrossNS_TXT_DKIM] = new RecommendationAdvice {
            Code = TtlCodes.UniformAcrossNS_TXT_DKIM,
            Title = "DKIM TXT TTL uniform across name servers",
            Why = "Consistent TTLs simplify caching and diagnostics.",
            How = "Keep TTLs aligned; target ≥3600s for selector TXT.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ttl", "dkim" }
        };
    }
}

