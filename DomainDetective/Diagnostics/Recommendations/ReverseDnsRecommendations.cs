using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class ReverseDnsRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[ReverseDnsCodes.TruncatedNoRecords] = new RecommendationAdvice {
            Code = ReverseDnsCodes.TruncatedNoRecords,
            Title = "Reverse DNS not found or truncated",
            Why = "Missing or truncated PTR records hinder diagnostics and may affect reputation checks.",
            How = "Ensure authoritative PTR exists for IPs and responses fit in UDP or allow TCP fallback.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr" }
        };

        map[ReverseDnsCodes.MalformedPtr] = new RecommendationAdvice {
            Code = ReverseDnsCodes.MalformedPtr,
            Title = "Malformed PTR record",
            Why = "Badly formatted PTR names can break reverse lookups and validation.",
            How = "Publish PTR names as valid FQDNs ending with a dot; avoid invalid characters.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1035" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr" }
        };

        map[ReverseDnsCodes.ForwardMismatch] = new RecommendationAdvice {
            Code = ReverseDnsCodes.ForwardMismatch,
            Title = "PTR does not forward-resolve to original IP",
            Why = "Reverse DNS should map back to the same IP to satisfy FCrDNS checks used by mail and reputation systems.",
            How = "Ensure the PTR hostname has an A/AAAA pointing back to the queried IP, or update PTR to the correct host.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1912#section-2.1" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr", "fcrdns" }
        };

        map[ReverseDnsCodes.SharedCloudManyToOne] = new RecommendationAdvice {
            Code = ReverseDnsCodes.SharedCloudManyToOne,
            Title = "PTR indicates shared cloud infrastructure",
            Why = "Many tenants may share IPs; reverse names often point to provider generic hosts which may not FCrDNS back to your domain.",
            How = "Consider dedicated reverse DNS or ensure sending hosts use IPs with PTR you control/aligned with HELO/EHLO.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr", "cloud" }
        };

        map[ReverseDnsCodes.PtrRecordPresent] = new RecommendationAdvice {
            Code = ReverseDnsCodes.PtrRecordPresent,
            Title = "PTR record present",
            Why = "Reverse DNS entries assist with logging and reputation checks.",
            How = "Maintain PTR records for all outbound IP addresses.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1912#section-2.1" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr" }
        };

        map[ReverseDnsCodes.PtrMatchesMx] = new RecommendationAdvice {
            Code = ReverseDnsCodes.PtrMatchesMx,
            Title = "PTR aligns with MX host",
            Why = "Matching PTR and MX names reduce spam scores and improve deliverability.",
            How = "Ensure PTR hostnames mirror the mail server's hostname.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr", "mx" }
        };

        map[ReverseDnsCodes.ForwardConfirmed] = new RecommendationAdvice {
            Code = ReverseDnsCodes.ForwardConfirmed,
            Title = "PTR forward-confirmed",
            Why = "Forward-confirmed reverse DNS assures the hostname resolves back to the original IP.",
            How = "Publish A/AAAA records for the PTR hostname pointing to the originating IP.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1912#section-2.1" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ptr", "fcrdns" }
        };
    }
}
