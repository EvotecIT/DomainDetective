using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class NSRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[NSCodes.Missing] = new RecommendationAdvice {
            Code = NSCodes.Missing,
            Title = "Publish authoritative NS records",
            Why = "Zones must list at least two authoritative nameservers for resilience and delegation.",
            How = "Add two or more NS records at the zone apex pointing to resolvable hostnames.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1912" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ns", "reliability" },
            Impact = "Resolvers may fail to locate your zone.",
            Effort = RecommendationEffort.Low,
            Verify = "Query NS at the apex; ensure at least two distinct hosts are returned."
        };
        map[NSCodes.Duplicate] = new RecommendationAdvice {
            Code = NSCodes.Duplicate,
            Title = "Remove duplicate NS entries",
            Why = "Duplicate NS values reduce effective diversity and provide no benefit.",
            How = "Ensure each NS record is unique; remove duplicates.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ns" },
            Impact = "Reduces redundancy and may mislead tooling.",
            Effort = RecommendationEffort.Low,
            Verify = "List NS; each hostname should appear once."
        };
        map[NSCodes.TooFewRecords] = new RecommendationAdvice {
            Code = NSCodes.TooFewRecords,
            Title = "Add at least two NS records",
            Why = "Operating a single nameserver creates a single point of failure.",
            How = "Publish a second authoritative NS on a distinct host/network.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "redundancy" },
            Impact = "Loss of service if the only NS is down.",
            Effort = RecommendationEffort.Medium,
            Verify = "NS query returns two or more distinct hosts."
        };
        map[NSCodes.CnameTarget] = new RecommendationAdvice {
            Code = NSCodes.CnameTarget,
            Title = "Avoid CNAMEs in NS hostnames",
            Why = "NS owner names must not point to CNAMEs; resolvers expect A/AAAA.",
            How = "Replace the CNAME with A/AAAA at the NS hostname or use the canonical host directly.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc1912#section-2.4" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ns", "cname" },
            Impact = "Resolution failures or added latency.",
            Effort = RecommendationEffort.Low,
            Verify = "Query the NS hostnames for A/AAAA; no CNAME should be returned."
        };
        map[NSCodes.MissingAddressRecords] = new RecommendationAdvice {
            Code = NSCodes.MissingAddressRecords,
            Title = "Ensure NS hostnames have A/AAAA",
            Why = "Resolvers must be able to reach NS hosts; missing addresses prevent that.",
            How = "Add A and/or AAAA records for each NS hostname.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ns", "glue" },
            Impact = "Authoritative service becomes unreachable.",
            Effort = RecommendationEffort.Low,
            Verify = "Query A/AAAA for each NS hostname; at least one must exist."
        };
        map[NSCodes.LowDiversity] = new RecommendationAdvice {
            Code = NSCodes.LowDiversity,
            Title = "Increase NS network diversity",
            Why = "Diverse networks/ASNs improve resilience against outages.",
            How = "Place NS hosts on different networks/providers where possible.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "resilience" },
            Impact = "Higher risk of correlated failures.",
            Effort = RecommendationEffort.Medium,
            Verify = "NS A/AAAA addresses span distinct subnets/ASNs."
        };
        map[NSCodes.HighDiversity] = new RecommendationAdvice {
            Code = NSCodes.HighDiversity,
            Title = "Authoritative NS are geographically diverse across networks/ASNs",
            Why = "Distribution across providers, networks, and regions improves resilience and latency.",
            How = "Maintain NS hosts on separate networks/providers to sustain diversity.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "resilience", "asn" },
            Impact = "Lower risk of correlated outages and better global performance.",
            Effort = RecommendationEffort.Low,
            Verify = "Geolocation/ASN checks show NS across distinct providers/ASNs."
        };
        map[NSCodes.DelegationMismatch] = new RecommendationAdvice {
            Code = NSCodes.DelegationMismatch,
            Title = "Align parent delegation with child NS set",
            Why = "Mismatch causes referral loops and intermittent resolution failures.",
            How = "Update registrar/parent zone NS to match the authoritative child zone.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "delegation", "registrar" },
            Impact = "Intermittent DNS failures across resolvers.",
            Effort = RecommendationEffort.Medium,
            Verify = "Parent NS set equals child zone NS set."
        };
        map[NSCodes.GlueIncomplete] = new RecommendationAdvice {
            Code = NSCodes.GlueIncomplete,
            Title = "Publish glue for in-bailiwick NS",
            Why = "In-bailiwick NS require glue A/AAAA at the parent to avoid circular dependencies.",
            How = "Add A/AAAA to parent (via registrar) for each in-bailiwick NS.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "glue" },
            Impact = "Resolvers may fail to resolve NS hostnames.",
            Effort = RecommendationEffort.Medium,
            Verify = "Parent additional section includes A/AAAA for in-bailiwick NS."
        };
        map[NSCodes.GlueInconsistent] = new RecommendationAdvice {
            Code = NSCodes.GlueInconsistent,
            Title = "Fix inconsistent glue vs child A/AAAA",
            Why = "Parent glue must match authoritative child addresses to avoid misrouting.",
            How = "Update either parent glue or child A/AAAA so both match.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "glue" },
            Impact = "Resolvers may reach stale or wrong servers.",
            Effort = RecommendationEffort.Low,
            Verify = "Parent glue equals child A/AAAA values."
        };
        map[NSCodes.RecursionOnAuthoritative] = new RecommendationAdvice {
            Code = NSCodes.RecursionOnAuthoritative,
            Title = "Disable recursion on authoritative NS",
            Why = "Authoritative servers should not perform recursion; it increases attack surface and cache poisoning risk.",
            How = "Configure the NS to serve authoritative data only (no-recursion).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "security" },
            Impact = "Potential abuse and data leakage via recursion.",
            Effort = RecommendationEffort.Low,
            Verify = "A test query for unrelated domains returns REFUSED or no recursion."
        };
    }
}
