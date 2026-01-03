using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class EdnsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[EdnsCodes.NotSupported] = new RecommendationAdvice {
            Code = EdnsCodes.NotSupported,
            Title = "Enable EDNS support on authoritative servers",
            Why = "EDNS allows larger DNS messages and is required by many modern features (DNSSEC, larger responses).",
            How = "Ensure your DNS software enables EDNS(0); upgrade or reconfigure servers and allow UDP payload ≥1232 bytes.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6891" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns" }
        };

        map[EdnsCodes.BufferTooLarge] = new RecommendationAdvice {
            Code = EdnsCodes.BufferTooLarge,
            Title = "EDNS UDP buffer too large (risk of fragmentation)",
            Why = "Advertising >1232 bytes over UDP can cause fragmentation and packet loss on common path MTUs.",
            How = "Configure EDNS UDP payload to 1232 or lower unless you control path MTU; enable TCP fallback.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8900" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "mtu" }
        };

        map[EdnsCodes.TruncatedFallback] = new RecommendationAdvice {
            Code = EdnsCodes.TruncatedFallback,
            Title = "EDNS responses truncated; TCP fallback used",
            Why = "Large DNS responses may require TCP fallback; ensure TCP/53 isn’t blocked by firewalls.",
            How = "Permit TCP/53 to authoritative servers and ensure DNS software handles truncation correctly.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7766" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "tcp" }
        };

        map[EdnsCodes.CookiesNotSupported] = new RecommendationAdvice {
            Code = EdnsCodes.CookiesNotSupported,
            Title = "DNS Cookies not supported",
            Why = "DNS Cookies (RFC 7873) help mitigate spoofing and some reflection/caching abuse by binding queries to a client.",
            How = "Enable DNS Cookies in your authoritative DNS software if supported; upgrade to a version that supports RFC 7873.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7873" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "cookies" },
            Impact = "Reduced resilience against certain spoofing and abuse scenarios.",
            Effort = RecommendationEffort.Medium,
            Verify = "Re-test EDNS; responses include the COOKIE option."
        };

        map[EdnsCodes.Supported] = new RecommendationAdvice {
            Code = EdnsCodes.Supported,
            Title = "Authoritative server supports EDNS",
            Why = "EDNS enables larger DNS messages and features like DNSSEC.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6891" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns" }
        };

        map[EdnsCodes.UdpSizeOk] = new RecommendationAdvice {
            Code = EdnsCodes.UdpSizeOk,
            Title = "EDNS UDP buffer within recommended limit",
            Why = "Limiting UDP payload to 1232 bytes avoids IP fragmentation on typical networks.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc8900" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "mtu" }
        };

        map[EdnsCodes.VersionZero] = new RecommendationAdvice {
            Code = EdnsCodes.VersionZero,
            Title = "EDNS version 0 in use",
            Why = "Version 0 is the only standardized EDNS version and ensures broad interoperability.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc6891" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns" }
        };

        map[EdnsCodes.CookiesSupported] = new RecommendationAdvice {
            Code = EdnsCodes.CookiesSupported,
            Title = "DNS Cookies supported",
            Why = "DNS Cookies improve DNS transaction security and help mitigate spoofing.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc7873" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "edns", "cookies" }
        };
    }
}
