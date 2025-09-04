using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class DnsHealthRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[DnsHealthCodes.SoaSerialSkew] = new RecommendationAdvice {
            Code = DnsHealthCodes.SoaSerialSkew,
            Title = "SOA serial numbers differ across NS",
            Why = "Authoritative name servers should serve identical zone data. Serial skew indicates replication or update lag.",
            How = "Ensure zone transfers/notifications complete. Verify primary/secondary synchronization and check for hidden primaries.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc1035" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "consistency" },
            Impact = "Clients may see inconsistent answers; DNSSEC signatures may not match if records differ.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query SOA serial from each NS and confirm they match.",
        };
        map[DnsHealthCodes.ApexInconsistent] = new RecommendationAdvice {
            Code = DnsHealthCodes.ApexInconsistent,
            Title = "A/AAAA answers for apex differ across NS",
            Why = "All authoritative servers should return the same RRset for the same name and class.",
            How = "Check zone contents on each nameserver; ensure updates are applied consistently and caches cleared.",
            Links = new [] { "https://datatracker.ietf.org/doc/html/rfc1034" },
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "consistency" },
            Impact = "Resolvers may receive different data depending on which NS they query.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query A/AAAA for the zone apex via each authoritative server and compare.",
        };
        map[DnsHealthCodes.SoaSerialConsistent] = new RecommendationAdvice {
            Code = DnsHealthCodes.SoaSerialConsistent,
            Title = "SOA serial numbers consistent across NS",
            Why = "Matching SOA serials show zone data is synchronized among authoritative servers.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "consistency" }
        };
        map[DnsHealthCodes.ServersResponsive] = new RecommendationAdvice {
            Code = DnsHealthCodes.ServersResponsive,
            Title = "Authoritative name servers responded to queries",
            Why = "Responsive authoritative servers improve resolver reliability and confidence.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "ns", "availability" }
        };
    }
}
