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
    }
}

