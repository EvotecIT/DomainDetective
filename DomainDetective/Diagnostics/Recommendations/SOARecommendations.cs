using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class SOARecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[SOACodes.Missing] = new RecommendationAdvice {
            Code = SOACodes.Missing,
            Title = "Publish SOA record",
            Why = "Zones must have a Start of Authority (SOA) record defining primary settings.",
            How = "Add one SOA record at the zone apex (MNAME, RNAME, serial, timers).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa" },
            Impact = "Zone may be considered misconfigured by resolvers and tooling.",
            Effort = RecommendationEffort.Low,
            Verify = "Query SOA at the apex; record should exist."
        };
        map[SOACodes.SerialFormatNonStandard] = new RecommendationAdvice {
            Code = SOACodes.SerialFormatNonStandard,
            Title = "Use YYYYMMDDnn SOA serial format",
            Why = "A date-based serial makes changes trackable and avoids rollbacks.",
            How = "Adopt a 10-digit serial: yyyyMMddNN (NN increments per day).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "serial" },
            Impact = "Non-standard serials complicate operations and validations.",
            Effort = RecommendationEffort.Low,
            Verify = "Serial is exactly 10 digits and begins with today's date when updated."
        };
        map[SOACodes.MnameInvalid] = new RecommendationAdvice {
            Code = SOACodes.MnameInvalid,
            Title = "Set a valid SOA MNAME",
            Why = "MNAME should be a valid primary authoritative nameserver hostname.",
            How = "Use a resolvable NS hostname as MNAME.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa" },
            Impact = "Inaccurate operational reference for zone maintenance.",
            Effort = RecommendationEffort.Low,
            Verify = "MNAME resolves to your primary authoritative server."
        };
        map[SOACodes.RnameInvalid] = new RecommendationAdvice {
            Code = SOACodes.RnameInvalid,
            Title = "Set a valid SOA RNAME",
            Why = "RNAME should contain a contact mailbox (with dot instead of @).",
            How = "Provide a valid mailbox in RNAME (e.g., hostmaster.example.com).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa" },
            Impact = "Operators may not receive notifications.",
            Effort = RecommendationEffort.Low,
            Verify = "RNAME follows mailbox syntax and is monitored."
        };
        map[SOACodes.RefreshExtreme] = new RecommendationAdvice {
            Code = SOACodes.RefreshExtreme,
            Title = "Tune SOA Refresh interval",
            Why = "Very low/high refresh increases traffic or slows convergence.",
            How = "Choose a refresh in the ~1–24h range appropriate for your change rate.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "timers" },
            Impact = "Unstable or sluggish secondary updates.",
            Effort = RecommendationEffort.Low,
            Verify = "Secondaries update within expected time frames."
        };
        map[SOACodes.RetryExtreme] = new RecommendationAdvice {
            Code = SOACodes.RetryExtreme,
            Title = "Tune SOA Retry interval",
            Why = "Excessive retry values delay recovery; tiny values cause noise.",
            How = "Set retry to a few minutes (e.g., 15m–2h).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "timers" },
            Impact = "Delayed resync on failure or unnecessary traffic.",
            Effort = RecommendationEffort.Low,
            Verify = "Secondaries retry at sensible cadence during outages."
        };
        map[SOACodes.MinimumExtreme] = new RecommendationAdvice {
            Code = SOACodes.MinimumExtreme,
            Title = "Set sensible negative cache (SOA minimum)",
            Why = "Very high negative TTL delays record appearance; very low adds load.",
            How = "Pick a negative TTL aligned with your change profile (~5–60m).",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "ttl" },
            Impact = "User-visible delays or unnecessary resolver load.",
            Effort = RecommendationEffort.Low,
            Verify = "NXDOMAIN caching duration matches policy."
        };
        map[SOACodes.RefreshSane] = new RecommendationAdvice {
            Code = SOACodes.RefreshSane,
            Title = "SOA Refresh interval within recommended range",
            Why = "Sensible refresh values keep secondaries updated without undue traffic.",
            How = "Maintain refresh between 30 minutes and 24 hours based on update needs.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "timers" },
            Impact = "Healthy secondary synchronization cadence.",
            Effort = RecommendationEffort.Low,
            Verify = "SOA Refresh is between 1800 and 86400 seconds."
        };
        map[SOACodes.RetrySane] = new RecommendationAdvice {
            Code = SOACodes.RetrySane,
            Title = "SOA Retry interval within recommended range",
            Why = "Balanced retry timing speeds recovery from transient failures.",
            How = "Keep retry around 5 minutes to 2 hours depending on operations.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "timers" },
            Impact = "Prompt retry without excessive load.",
            Effort = RecommendationEffort.Low,
            Verify = "SOA Retry is between 300 and 7200 seconds."
        };
        map[SOACodes.ExpireSane] = new RecommendationAdvice {
            Code = SOACodes.ExpireSane,
            Title = "SOA Expire interval within recommended range",
            Why = "Appropriate expire ensures stale zones are discarded after extended outages.",
            How = "Use an expire around 1–4 weeks depending on tolerance for stale data.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "timers" },
            Impact = "Secondaries drop obsolete zones in a timely manner.",
            Effort = RecommendationEffort.Low,
            Verify = "SOA Expire is between 604800 and 2419200 seconds."
        };
        map[SOACodes.MnameMatchesNs] = new RecommendationAdvice {
            Code = SOACodes.MnameMatchesNs,
            Title = "SOA primary NS matches published NS records",
            Why = "MNAME should point to an authoritative NS for operational consistency.",
            How = "Use one of the zone's NS hostnames as the SOA MNAME.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "dns", "soa", "ns" },
            Impact = "Accurate reference for zone maintenance and transfers.",
            Effort = RecommendationEffort.Low,
            Verify = "SOA MNAME hostname appears in the NS RRset."
        };
    }
}
