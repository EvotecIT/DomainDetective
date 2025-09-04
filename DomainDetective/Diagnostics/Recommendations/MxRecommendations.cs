using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class MxRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[MxCodes.Missing] = new RecommendationAdvice {
            Code = MxCodes.Missing,
            Title = "Publish MX records",
            Why = "Without MX records, mail delivery relies on A/AAAA fallback and may fail across receivers.",
            How = "Add one or more MX records with correct priorities pointing to resolvable mail hosts.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "smtp" }
        };
        map[MxCodes.CnameTarget] = new RecommendationAdvice {
            Code = MxCodes.CnameTarget,
            Title = "Avoid CNAMEs as MX targets",
            Why = "RFC 2181 prohibits MX pointing at CNAMEs; receivers may treat this as misconfiguration.",
            How = "Point MX directly at canonical hostnames with A/AAAA records.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc2181#section-10.3" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns" }
        };
        map[MxCodes.IpTarget] = new RecommendationAdvice {
            Code = MxCodes.IpTarget,
            Title = "Do not point MX at IP addresses",
            Why = "MX must point to hostnames which in turn resolve to addresses.",
            How = "Create a hostname (A/AAAA) for the mail server and reference that in the MX record.",
            Links = new [] { "https://www.rfc-editor.org/rfc/rfc5321#section-2.3.5" },
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns" }
        };
        map[MxCodes.TargetNonExistent] = new RecommendationAdvice {
            Code = MxCodes.TargetNonExistent,
            Title = "Fix MX hostname NXDOMAIN",
            Why = "MX targets must exist and resolve; otherwise mail cannot be delivered.",
            How = "Ensure NS and A/AAAA records exist for each MX target (and correct typos).",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns" }
        };
        map[MxCodes.TargetNoAddressRecords] = new RecommendationAdvice {
            Code = MxCodes.TargetNoAddressRecords,
            Title = "Add A/AAAA to MX host",
            Why = "MX targets require address records to accept mail.",
            How = "Publish A and/or AAAA for each MX host.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns" }
        };
        map[MxCodes.PrioritiesOutOfOrder] = new RecommendationAdvice {
            Code = MxCodes.PrioritiesOutOfOrder,
            Title = "Normalize MX priorities",
            Why = "Misordered priorities can confuse troubleshooting and automated tooling.",
            How = "Use ascending MX preference values; duplicates are allowed to load-balance.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx" }
        };
        map[MxCodes.NoBackupServers] = new RecommendationAdvice {
            Code = MxCodes.NoBackupServers,
            Title = "Add a backup MX",
            Why = "A single MX creates a single point of failure for inbound mail.",
            How = "Publish an additional MX with a higher preference, hosted independently where possible.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "resilience" }
        };
        map[MxCodes.NullMxPresent] = new RecommendationAdvice {
            Code = MxCodes.NullMxPresent,
            Title = "Null MX indicates no inbound mail",
            Why = "A 0 . MX signals the domain does not accept mail; ensure this is intentional.",
            How = "If you intend to receive mail, remove Null MX and publish valid MX hosts.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx" }
        };
        map[MxCodes.LocalhostTarget] = new RecommendationAdvice {
            Code = MxCodes.LocalhostTarget,
            Title = "Avoid localhost in MX",
            Why = "Localhost targets are not routable for external senders.",
            How = "Point MX at a reachable external hostname.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx" }
        };

        map[MxCodes.RrsetInconsistentAcrossNs] = new RecommendationAdvice {
            Code = MxCodes.RrsetInconsistentAcrossNs,
            Title = "MX RRset differs across name servers",
            Why = "Authoritative NS should serve identical MX RRsets; divergence indicates propagation or zone transfer issues.",
            How = "Verify zone is fully propagated and AXFR/IXFR completed; ensure all NS have current zone data.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns", "ns" },
            Impact = "Senders may see inconsistent routing and delivery failures.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query each NS for MX and confirm identical answers."
        };

        map[MxCodes.TargetAddressInconsistentAcrossNs] = new RecommendationAdvice {
            Code = MxCodes.TargetAddressInconsistentAcrossNs,
            Title = "MX host addresses differ across name servers",
            Why = "A/AAAA RRsets for MX hosts should be consistent across NS; differences can cause flapping routes.",
            How = "Ensure address records are synchronized across all authoritative servers and not cached stale.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns", "ns" },
            Impact = "Mail delivery may be inconsistent depending on resolver path.",
            Effort = RecommendationEffort.Medium,
            Verify = "Query A/AAAA for MX hosts on each NS and compare results."
        };

        map[MxCodes.TtlNonUniform] = new RecommendationAdvice {
            Code = MxCodes.TtlNonUniform,
            Title = "Normalize MX RRset TTLs",
            Why = "Mixed TTLs on the same RRset can create non-deterministic caching behavior.",
            How = "Set identical TTL values on all MX records for the zone.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns", "ttl" },
            Effort = RecommendationEffort.Low,
            Verify = "dig +ttlid mx example.com shows equal TTLs."
        };

        map[MxCodes.TargetTtlNonUniform] = new RecommendationAdvice {
            Code = MxCodes.TargetTtlNonUniform,
            Title = "Normalize A/AAAA TTLs for MX hosts",
            Why = "Large TTL discrepancies for MX host addresses may cause uneven cache aging.",
            How = "Use consistent TTLs across A/AAAA records for each MX host where operationally feasible.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "dns", "ttl" },
            Effort = RecommendationEffort.Low,
            Verify = "dig +ttlid A/AAAA mx1.example.com shows equal TTLs."
        };

        map[MxCodes.RedundantHosts] = new RecommendationAdvice {
            Code = MxCodes.RedundantHosts,
            Title = "Redundant MX hosts configured",
            Why = "Multiple MX hosts improve resilience and availability of inbound mail.",
            How = "Maintain at least two MX records with differing preferences hosted on separate infrastructure.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "resilience" }
        };

        map[MxCodes.TlsSupported] = new RecommendationAdvice {
            Code = MxCodes.TlsSupported,
            Title = "MX hosts support STARTTLS",
            Why = "TLS encryption protects email in transit and is widely expected by modern mail servers.",
            How = "Keep TLS enabled and certificates valid on all MX hosts.",
            Domain = RecommendationDomain.EmailAuth,
            Tags = new [] { "mx", "tls" }
        };
    }
}

