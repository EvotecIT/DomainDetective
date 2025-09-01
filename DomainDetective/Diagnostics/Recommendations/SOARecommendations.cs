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
    }
}
