using System.Collections.Generic;

namespace DomainDetective.Recommendations;

internal sealed class WhoisRecommendations : IRecommendationProvider {
    public void Register(IDictionary<string, RecommendationAdvice> map) {
        map[WhoisCodes.ExpirySoon] = new RecommendationAdvice {
            Code = WhoisCodes.ExpirySoon,
            Title = "Renew domain before expiry",
            Why = "Imminent expiry risks service disruption and domain loss.",
            How = "Renew with the registrar and ensure auto-renew is enabled where appropriate.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "expiry" },
            Impact = "Loss of domain control and outages.",
            Effort = RecommendationEffort.Low,
            Verify = "WHOIS shows extended expiry date; RDAP confirms change."
        };
        map[WhoisCodes.Expired] = new RecommendationAdvice {
            Code = WhoisCodes.Expired,
            Title = "Domain appears expired",
            Why = "Expired domains may be suspended, parked, or re-registered by third parties.",
            How = "Contact the registrar immediately to restore the domain if within grace period.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "expiry" },
            Impact = "Service outage and potential domain loss.",
            Effort = RecommendationEffort.Medium,
            Verify = "WHOIS/RDAP shows active status with new expiry."
        };
        map[WhoisCodes.NoRegistrar] = new RecommendationAdvice {
            Code = WhoisCodes.NoRegistrar,
            Title = "Registrar not identified",
            Why = "Missing registrar data hinders operations and support.",
            How = "Check WHOIS server or use RDAP to identify registrar; update records if needed.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "registrar" },
            Impact = "Operational risk and delayed support.",
            Effort = RecommendationEffort.Low,
            Verify = "Registrar name present in WHOIS/RDAP."
        };
        map[WhoisCodes.ParseAnomaly] = new RecommendationAdvice {
            Code = WhoisCodes.ParseAnomaly,
            Title = "WHOIS parse anomaly",
            Why = "Inconsistent WHOIS formats can hide critical fields (e.g., expiry).",
            How = "Review raw WHOIS; rely on RDAP where possible for structured data.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "parsing" },
            Impact = "Uncertain domain lifecycle posture.",
            Effort = RecommendationEffort.Low,
            Verify = "WHOIS/RDAP data validated with correct expiry/registrar."
        };
        map[WhoisCodes.QueryFailed] = new RecommendationAdvice {
            Code = WhoisCodes.QueryFailed,
            Title = "WHOIS query failed",
            Why = "Network or server error prevented WHOIS retrieval.",
            How = "Retry from a stable network; try alternative WHOIS servers if TLD-specific.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "network" },
            Impact = "Uncertain domain registration posture.",
            Effort = RecommendationEffort.Low,
            Verify = "WHOIS response retrieved successfully."
        };
        map[WhoisCodes.ContactValid] = new RecommendationAdvice {
            Code = WhoisCodes.ContactValid,
            Title = "WHOIS contact details available",
            Why = "Published contact information helps reach the domain owner for operational or abuse issues.",
            How = "Ensure registrar and registrant contact fields remain accurate and complete.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "contact" },
            Impact = "Improves accountability and facilitates communication.",
            Effort = RecommendationEffort.Low,
            Verify = "WHOIS publishes reachable email or telephone data."
        };
        map[WhoisCodes.ExpiryFuture] = new RecommendationAdvice {
            Code = WhoisCodes.ExpiryFuture,
            Title = "Domain not near expiry",
            Why = "A long registration period indicates the domain is under stable control.",
            How = "Monitor renewal reminders and maintain auto-renew to keep ownership.",
            Domain = RecommendationDomain.Infrastructure,
            Tags = new [] { "whois", "expiry" },
            Impact = "Low risk of unexpected domain lapse.",
            Effort = RecommendationEffort.Low,
            Verify = "WHOIS shows expiration date well into the future."
        };
    }
}

